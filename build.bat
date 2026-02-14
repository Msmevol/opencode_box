@echo off
call "C:\apps\vs\desktop\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d C:\project\box_opencode_2
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release 2>&1
if errorlevel 1 (
    echo CMAKE_CONFIGURE_FAILED
    exit /b 1
)
cmake --build build 2>&1
if errorlevel 1 (
    echo CMAKE_BUILD_FAILED
    exit /b 1
)
echo BUILD_SUCCESS
