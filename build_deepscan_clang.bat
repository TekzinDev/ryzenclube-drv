@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  Build DeepScan.sys with Clang-CL + o-LLVM obfuscation
::
::  Usage:
::    build_deepscan_clang.bat            - build with obfuscation
::    build_deepscan_clang.bat nollvm     - build without obfuscation
:: ============================================================

set "CLANG=C:\Program Files\LLVM\bin\clang-cl.exe"
set "LINKER=C:\Program Files\LLVM\bin\lld-link.exe"

set "MSVC_VER=14.44.35207"
set "SDK_VER=10.0.26100.0"

:: Kernel-mode include paths (WDK km + shared + MSVC CRT headers for basic types)
set "INCLUDE=C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\km\crt;C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\km;C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\shared;C:\Program Files (x86)\Windows Kits\10\Include\%SDK_VER%\ucrt;C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\%MSVC_VER%\include"

:: Kernel-mode lib path
set "LIB=C:\Program Files (x86)\Windows Kits\10\Lib\%SDK_VER%\km\x64"

set "SRC_DIR=%~dp0DeepScan"
set "OUT_DIR=%~dp0DeepScan\x64\Release"
set "OUT_SYS=!OUT_DIR!\DeepScan.sys"

:: o-LLVM plugin path
set "OLLVM_DLL=%~dp0LLVMObfuscator.dll"

:: Default: obfuscation ON
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

if defined OBF_PASSES (
    set "LLVM_OBF_SCALAROPTIMIZERLATE_PASSES=!OBF_PASSES!"
)

:: ============================================================
::  Compile (kernel mode)
:: ============================================================
echo [*] Compiling DeepScan.sys with Clang-CL (kernel mode)...
cd /d "!SRC_DIR!"

"!CLANG!" /kernel /GS- /std:c++17 /O2 /Zl -g0 -fno-builtin-memset -fno-builtin-memcpy -fno-exceptions -mstack-probe-size=999999 -D_AMD64_ -D_WIN64 -D_KERNEL_MODE -DNTDDI_VERSION=0x0A000000 -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH -D_CRTIMP= -D_CRTIMP_ALT= -D"__ALTDECL=__cdecl" -D_CRT_SECURE_NO_WARNINGS -Wno-everything !PLUGIN_FLAG! /c main.cpp /FoDeepScan_clang.obj

if !ERRORLEVEL! NEQ 0 (
    echo [!] Compilation FAILED
    exit /b 1
)

:: ============================================================
::  Link (kernel driver)
:: ============================================================
if not exist "!OUT_DIR!" mkdir "!OUT_DIR!"
echo [*] Linking with lld-link (NATIVE driver)...

"!LINKER!" /NODEFAULTLIB /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /MAP /OUT:"!OUT_SYS!" DeepScan_clang.obj ntoskrnl.lib hal.lib

if !ERRORLEVEL! NEQ 0 (
    echo [!] Linking FAILED
    exit /b 1
)

:: ============================================================
::  Done
:: ============================================================
echo.
echo [+] Build SUCCESS: !OUT_SYS!
for %%A in ("!OUT_SYS!") do echo [+] Size: %%~zA bytes
echo.

del /q DeepScan_clang.obj 2>nul

endlocal
