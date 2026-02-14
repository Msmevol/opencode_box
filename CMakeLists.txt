cmake_minimum_required(VERSION 3.20)
project(opencode_box C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Prevent winsock.h vs winsock2.h conflicts globally
add_compile_definitions(WIN32_LEAN_AND_MEAN)

# MSVC: treat source and execution charset as UTF-8
if(MSVC)
    add_compile_options(/utf-8)
endif()

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

# --- Hook DLL (built first for embedding into EXE) ---
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
target_link_libraries(sandbox_hook PRIVATE sandbox_common detours ws2_32 advapi32)

# Force DLL output to a known path for resource embedding
set_target_properties(sandbox_hook PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/hookdll_out"
)

# Generate .rc file that embeds the hook DLL binary
set(SANDBOX_HOOK_DLL_PATH "${CMAKE_BINARY_DIR}/hookdll_out/sandbox_hook.dll")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/launcher/sandbox_hook.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sandbox_hook.rc"
    @ONLY
)

# --- Launcher executable (single EXE with embedded DLL) ---
add_executable(sandbox
    src/launcher/main.c
    src/launcher/sandbox.c
    src/launcher/injector.c
    src/launcher/ipc_server.c
    src/common/logger.c
    "${CMAKE_CURRENT_BINARY_DIR}/sandbox_hook.rc"
)
target_include_directories(sandbox PRIVATE src/launcher src/common)
target_link_libraries(sandbox PRIVATE sandbox_common detours advapi32 userenv)
add_dependencies(sandbox sandbox_hook)

# Ensure .rc compilation waits for the DLL file to exist (file-level dependency)
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/sandbox_hook.rc" PROPERTIES
    OBJECT_DEPENDS "${SANDBOX_HOOK_DLL_PATH}"
)

# --- Test target ---
add_executable(test_target tests/test_target.c)
target_link_libraries(test_target PRIVATE ws2_32 advapi32)
