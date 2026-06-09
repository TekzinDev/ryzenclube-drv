@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  Build ConsoleApplication7 with Clang-CL + o-LLVM obfuscation
::
::  Usage:
::    build_clang.bat            - build with obfuscation (default)
::    build_clang.bat nollvm     - build without obfuscation
:: ============================================================

set "CLANG=C:\Program Files\LLVM\bin\clang-cl.exe"
set "LINKER=C:\Program Files\LLVM\bin\lld-link.exe"
set "MT=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\mt.exe"

set "MSVC_VER=14.44.35207"
set "SDK_VER=10.0.26100.0"

set "INCLUDE=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\%MSVC_VER%\include;C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\um;C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\shared"

set "LIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\%MSVC_VER%\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%\ucrt\x64"

set "SRC_DIR=%~dp0ConsoleApplication7"
set "OUT_DIR=%~dp0x64\Release"
set "OUT_EXE=!OUT_DIR!\scanner_clang.exe"

:: o-LLVM plugin path
set "OLLVM_DLL=%~dp0LLVMObfuscator.dll"

:: Default: obfuscation ON, unless "nollvm" argument is passed
set "PLUGIN_FLAG=-fpass-plugin="!OLLVM_DLL!""
set "OBF_PASSES=substitution,flattening,bogus,split-basic-blocks"

if /i "%~1"=="nollvm" (
    set "PLUGIN_FLAG="
    set "OBF_PASSES="
    echo [*] Obfuscation DISABLED
) else (
    echo [*] o-LLVM plugin: !OLLVM_DLL!
    echo [*] Passes: !OBF_PASSES!
)

:: Set o-LLVM environment variables for pass selection
if defined OBF_PASSES (
    set "LLVM_OBF_SCALAROPTIMIZERLATE_PASSES=!OBF_PASSES!"
)

:: ============================================================
::  Compile
:: ============================================================
echo [*] Compiling with Clang-CL...
cd /d "!SRC_DIR!"

"!CLANG!" /GS- /std:c++20 /O2 /Zl -fno-builtin-memset -fno-builtin-memcpy -fno-exceptions -mstack-probe-size=999999 -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH -Wno-everything !PLUGIN_FLAG! /c ConsoleApplication7.cpp /FoConsoleApplication7_clang.obj

if !ERRORLEVEL! NEQ 0 (
    echo [!] Compilation FAILED
    exit /b 1
)

:: ============================================================
::  Link
:: ============================================================
if not exist "!OUT_DIR!" mkdir "!OUT_DIR!"
echo [*] Linking with lld-link...

"!LINKER!" /NODEFAULTLIB /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE /MAP /OUT:"!OUT_EXE!" ConsoleApplication7_clang.obj

if !ERRORLEVEL! NEQ 0 (
    echo [!] Linking FAILED
    exit /b 1
)

:: ============================================================
::  Embed manifest (requireAdministrator)
:: ============================================================
echo [*] Embedding manifest...

"!MT!" -nologo -manifest app.manifest -outputresource:"!OUT_EXE!;#1"

if !ERRORLEVEL! NEQ 0 (
    echo [!] Manifest embed FAILED
    exit /b 1
)

:: ============================================================
::  Done
:: ============================================================
echo.
echo [+] Build SUCCESS: !OUT_EXE!
for %%A in ("!OUT_EXE!") do echo [+] Size: %%~zA bytes
echo.

del /q ConsoleApplication7_clang.obj 2>nul

endlocal
