#include "hooks_network.h"
#include "hook_policy.h"
#include "ipc_client.h"
#include "ipc_protocol.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <detours.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

/* ===== Original function pointers ===== */

/* DNS resolution hooks — domain-level whitelist enforcement */
static INT (WSAAPI *Real_getaddrinfo)(
    PCSTR pNodeName, PCSTR pServiceName,
    const ADDRINFOA *pHints, PADDRINFOA *ppResult) = getaddrinfo;

static INT (WSAAPI *Real_GetAddrInfoW)(
    PCWSTR pNodeName, PCWSTR pServiceName,
    const ADDRINFOW *pHints, PADDRINFOW *ppResult) = GetAddrInfoW;

/* Connection hooks — fallback IP-level deny-all for non-loopback */
static int (WSAAPI *Real_connect)(SOCKET, const struct sockaddr *, int) = connect;
static int (WSAAPI *Real_WSAConnect)(SOCKET, const struct sockaddr *, int,
    LPWSABUF, LPWSABUF, LPQOS, LPQOS) = WSAConnect;
static int (WSAAPI *Real_sendto)(SOCKET, const char *, int, int,
    const struct sockaddr *, int) = sendto;

/* ===== Helpers ===== */

static int is_loopback_addr(const struct sockaddr *addr) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        /* 127.0.0.0/8 */
        return (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        /* ::1 */
        static const unsigned char lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return memcmp(&sin6->sin6_addr, lo, 16) == 0;
    }
    return 0;
}

static void addr_to_str(const struct sockaddr *addr, char *buf, size_t buflen) {
    buf[0] = '\0';
    if (!addr) return;
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, (socklen_t)buflen);
    } else if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, (socklen_t)buflen);
    }
}

/* ===== DNS Hooks (domain whitelist) ===== */

static INT WSAAPI Hooked_getaddrinfo(
    PCSTR pNodeName, PCSTR pServiceName,
    const ADDRINFOA *pHints, PADDRINFOA *ppResult)
{
    if (pNodeName && pNodeName[0]) {
        const SandboxPolicy *policy = hook_policy_get();
        if (policy) {
            PolicyAction action = policy_check_domain(policy, pNodeName);
            if (action == POLICY_DENY) {
                wchar_t msg[512];
                swprintf(msg, 512, L"DENIED DNS resolve: %hs", pNodeName);
                ipc_client_log(IPC_RESOURCE_NETWORK, msg);
                return WSAHOST_NOT_FOUND;
            }
            {
                wchar_t msg[512];
                swprintf(msg, 512, L"ALLOWED DNS resolve: %hs", pNodeName);
                ipc_client_log(IPC_RESOURCE_NETWORK, msg);
            }
        }
    }
    return Real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

static INT WSAAPI Hooked_GetAddrInfoW(
    PCWSTR pNodeName, PCWSTR pServiceName,
    const ADDRINFOW *pHints, PADDRINFOW *ppResult)
{
    if (pNodeName && pNodeName[0]) {
        const SandboxPolicy *policy = hook_policy_get();
        if (policy) {
            /* Convert wide domain to narrow for policy check */
            char domain_a[MAX_DOMAIN_LEN];
            WideCharToMultiByte(CP_UTF8, 0, pNodeName, -1,
                                domain_a, sizeof(domain_a), NULL, NULL);

            PolicyAction action = policy_check_domain(policy, domain_a);
            if (action == POLICY_DENY) {
                wchar_t msg[512];
                swprintf(msg, 512, L"DENIED DNS resolve: %s", pNodeName);
                ipc_client_log(IPC_RESOURCE_NETWORK, msg);
                return WSAHOST_NOT_FOUND;
            }
            {
                wchar_t msg[512];
                swprintf(msg, 512, L"ALLOWED DNS resolve: %s", pNodeName);
                ipc_client_log(IPC_RESOURCE_NETWORK, msg);
            }
        }
    }
    return Real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

/* ===== Connection Hooks (IP-level fallback: allow loopback, deny rest) ===== */

static int WSAAPI Hooked_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    if (name && !is_loopback_addr(name)) {
        const SandboxPolicy *policy = hook_policy_get();
        if (policy && policy->domain_whitelist_count > 0) {
            /* If domain whitelist is active, block direct IP connections
               to non-loopback addresses. Legitimate traffic goes through
               DNS first (which we already filtered). Direct IP connections
               bypass DNS and should be blocked. */
            char ip[128];
            addr_to_str(name, ip, sizeof(ip));
            wchar_t msg[512];
            swprintf(msg, 512, L"DENIED direct IP connect: %hs (use domain name)", ip);
            ipc_client_log(IPC_RESOURCE_NETWORK, msg);
            WSASetLastError(WSAEACCES);
            return SOCKET_ERROR;
        }
    }
    return Real_connect(s, name, namelen);
}

static int WSAAPI Hooked_WSAConnect(SOCKET s, const struct sockaddr *name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
    LPQOS lpSQOS, LPQOS lpGQOS)
{
    if (name && !is_loopback_addr(name)) {
        const SandboxPolicy *policy = hook_policy_get();
        if (policy && policy->domain_whitelist_count > 0) {
            char ip[128];
            addr_to_str(name, ip, sizeof(ip));
            wchar_t msg[512];
            swprintf(msg, 512, L"DENIED direct IP WSAConnect: %hs", ip);
            ipc_client_log(IPC_RESOURCE_NETWORK, msg);
            WSASetLastError(WSAEACCES);
            return SOCKET_ERROR;
        }
    }
    return Real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

static int WSAAPI Hooked_sendto(SOCKET s, const char *buf, int len, int flags,
    const struct sockaddr *to, int tolen)
{
    if (to && !is_loopback_addr(to)) {
        const SandboxPolicy *policy = hook_policy_get();
        if (policy && policy->domain_whitelist_count > 0) {
            WSASetLastError(WSAEACCES);
            return SOCKET_ERROR;
        }
    }
    return Real_sendto(s, buf, len, flags, to, tolen);
}

/* ===== Install / Uninstall ===== */

void hooks_network_install(void) {
    /* DNS hooks */
    DetourAttach(&(PVOID)Real_getaddrinfo, Hooked_getaddrinfo);
    DetourAttach(&(PVOID)Real_GetAddrInfoW, Hooked_GetAddrInfoW);
    /* Connection hooks */
    DetourAttach(&(PVOID)Real_connect, Hooked_connect);
    DetourAttach(&(PVOID)Real_WSAConnect, Hooked_WSAConnect);
    DetourAttach(&(PVOID)Real_sendto, Hooked_sendto);
}

void hooks_network_uninstall(void) {
    DetourDetach(&(PVOID)Real_getaddrinfo, Hooked_getaddrinfo);
    DetourDetach(&(PVOID)Real_GetAddrInfoW, Hooked_GetAddrInfoW);
    DetourDetach(&(PVOID)Real_connect, Hooked_connect);
    DetourDetach(&(PVOID)Real_WSAConnect, Hooked_WSAConnect);
    DetourDetach(&(PVOID)Real_sendto, Hooked_sendto);
}
