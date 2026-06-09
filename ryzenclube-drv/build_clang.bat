@echo off
set "CLANG=C:\Program Files\LLVM\bin\clang-cl.exe"
set "MSVC_VER=14.44.35207"
set "SDK_VER=10.0.26100.0"
set "MSVC_INC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\%MSVC_VER%\include"
set "SDK_UM_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\um"
set "SDK_UCRT_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\ucrt"
set "SDK_SHARED_INC=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\shared"
set "MSVC_LIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\%MSVC_VER%\lib\x64"
set "SDK_UM_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%\um\x64"
set "SDK_UCRT_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%\ucrt\x64"

"%CLANG%" /GS- /std:c++20 /O2 /Zl -fno-builtin-memset -fno-builtin-memcpy -Wno-pragma-pack -Wno-unknown-pragmas -I"%MSVC_INC%" -I"%SDK_UM_INC%" -I"%SDK_UCRT_INC%" -I"%SDK_SHARED_INC%" ConsoleApplication7.cpp /Fe"..\x64\Release\scanner_clang.exe" /link /NODEFAULTLIB /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE "/LIBPATH:%MSVC_LIB%" "/LIBPATH:%SDK_UM_LIB%" "/LIBPATH:%SDK_UCRT_LIB%" kernel32.lib

if %ERRORLEVEL% EQU 0 (
    echo BUILD_SUCCESS
) else (
    echo BUILD_FAILED errorlevel=%ERRORLEVEL%
)
