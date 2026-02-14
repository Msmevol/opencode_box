cmake_minimum_required(VERSION 3.20)
project(opencode_box C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Prevent winsock.h vs winsock2.h conflicts globally
add_compile_definitions(WIN32_LEAN_AND_MEAN)

# --- Third-party: cJSON ---
add_library(cjson STATIC extern/cJSON/cJSON.c)
target_include_directories(cjson PUBLIC extern/cJSON)

# --- Third-party: Detours ---
set(DETOURS_SRC
    extern/detours/src/detours.cpp
    extern/detours/src/modules.cpp
    extern/detours/src/disasm.cpp
    extern/detours/src/image.cpp
    extern/detours/src/creatwth.cpp
)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND DETOURS_SRC extern/detours/src/disolx64.cpp)
else()
    list(APPEND DETOURS_SRC extern/detours/src/disolx86.cpp)
endif()

add_library(detours STATIC ${DETOURS_SRC})
target_include_directories(detours PUBLIC extern/detours/src)
target_compile_definitions(detours PRIVATE WIN32_LEAN_AND_MEAN)

# --- Common library ---
add_library(sandbox_common STATIC
    src/common/policy.c
    src/common/path_match.c
)
target_include_directories(sandbox_common PUBLIC src/common)
target_link_libraries(sandbox_common PRIVATE cjson)

# --- Launcher executable ---
add_executable(sandbox
    src/launcher/main.c
    src/launcher/sandbox.c
    src/launcher/injector.c
    src/launcher/ipc_server.c
)
target_include_directories(sandbox PRIVATE src/launcher src/common)
target_link_libraries(sandbox PRIVATE sandbox_common cjson detours advapi32 userenv)

# --- Hook DLL ---
add_library(sandbox_hook SHARED
    src/hookdll/dllmain.c
    src/hookdll/hooks_file.c
    src/hookdll/hooks_network.c
    src/hookdll/hooks_registry.c
    src/hookdll/hooks_process.c
    src/hookdll/ipc_client.c
    src/hookdll/hook_policy.c
)
target_include_directories(sandbox_hook PRIVATE src/hookdll src/common extern/detours/src)
target_link_libraries(sandbox_hook PRIVATE sandbox_common cjson detours ws2_32 advapi32)

# --- Test target ---
add_executable(test_target tests/test_target.c)
target_link_libraries(test_target PRIVATE ws2_32 advapi32)
