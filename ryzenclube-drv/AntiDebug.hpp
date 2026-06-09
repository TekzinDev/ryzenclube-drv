#pragma once
#include <windows.h>

#include "XorStr.hpp"
#include "IndirectSyscall.hpp"

// =============================================
//  AntiDebug.hpp
//
//  Continuous anti-debug checks via ISYSCALL.
//  Called before each critical detection check
//  to catch debuggers attached AFTER startup.
//
//  Checks:
//    1. ProcessDebugPort (class 7)
//    2. ProcessDebugObjectHandle (class 30)
//    3. ProcessDebugFlags (class 31)
//    4. PEB->BeingDebugged
//    5. Hardware breakpoints (DR0-DR3) on our code
//
//  All calls go through indirect syscalls —
//  immune to usermode hooking of NtQueryInformationProcess.
// =============================================

namespace AntiDebug {

    // =============================================
    //  1. ProcessDebugPort (class 7)
    //  Non-zero = debugger is attached
    //  Most reliable — kernel sets this on NtDebugActiveProcess
    // =============================================

    __forceinline bool CheckDebugPort() {
        ULONG_PTR debugPort = 0;
        NTSTATUS st = ISYSCALL(NtQueryInformationProcess)(
            (HANDLE)-1,          // current process
            (ULONG)7,            // ProcessDebugPort
            (PVOID)&debugPort,
            (ULONG)sizeof(debugPort),
            (PULONG)NULL);

        return (NT_SUCCESS(st) && debugPort != 0);
    }

    // =============================================
    //  2. ProcessDebugObjectHandle (class 30)
    //  If kernel returns STATUS_SUCCESS, a debug object exists
    //  STATUS_PORT_NOT_SET (0xC0000353) = no debugger
    // =============================================

    __forceinline bool CheckDebugObject() {
        HANDLE debugObj = NULL;
        NTSTATUS st = ISYSCALL(NtQueryInformationProcess)(
            (HANDLE)-1,
            (ULONG)30,          // ProcessDebugObjectHandle
            (PVOID)&debugObj,
            (ULONG)sizeof(debugObj),
            (PULONG)NULL);

        // SUCCESS = debug object exists = debugger attached
        return NT_SUCCESS(st);
    }

    // =============================================
    //  3. ProcessDebugFlags (class 31)
    //  Returns NoDebugInherit flag
    //  0 = debugger is present, 1 = no debugger
    // =============================================

    __forceinline bool CheckDebugFlags() {
        ULONG debugFlags = 1;
        NTSTATUS st = ISYSCALL(NtQueryInformationProcess)(
            (HANDLE)-1,
            (ULONG)31,          // ProcessDebugFlags
            (PVOID)&debugFlags,
            (ULONG)sizeof(debugFlags),
            (PULONG)NULL);

        return (NT_SUCCESS(st) && debugFlags == 0);
    }

    // =============================================
    //  4. PEB->BeingDebugged (offset 0x02)
    //  Direct PEB read — no API call to hook
    //  Set by kernel when debugger attaches
    // =============================================

    __forceinline bool CheckPEBDebugFlag() {
#if defined(_M_X64) || defined(__amd64__)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        return (peb[2] != 0);  // BeingDebugged at offset 0x02
    }

    // =============================================
    //  5. Hardware breakpoints (DR0-DR3)
    //  Check if any debug register is set at all
    //  Catches BPs on our code AND ntdll
    //  Runs via ISYSCALL — unhookable
    // =============================================

    __forceinline bool CheckHWBP() {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        NTSTATUS st = ISYSCALL(NtGetContextThread)((HANDLE)-2, &ctx);
        if (!NT_SUCCESS(st))
            return false;

        // Any enabled breakpoint in DR7 = suspicious
        // Bits 0,2,4,6 are local enable for DR0-DR3
        DWORD64 dr7 = ctx.Dr7;
        if (dr7 & 0x55)  // any of bits 0,2,4,6 set
            return true;

        // Also check if any DR has a non-zero address even without DR7 enable
        // (some debuggers clear DR7 but leave addresses)
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return true;

        return false;
    }

    // =============================================
    //  Combined check — returns true if ANY debugger detected
    // =============================================

    __declspec(noinline) bool IsDebuggerAttached() {
        if (CheckDebugPort())   return true;
        if (CheckDebugObject()) return true;
        if (CheckDebugFlags())  return true;
        if (CheckPEBDebugFlag()) return true;
        if (CheckHWBP())        return true;
        return false;
    }

    // =============================================
    //  Debug gate — call before critical operations
    //  If debugger detected, terminate immediately.
    //  No message, no cleanup — instant death.
    //  This makes it very hard to single-step through
    //  detection logic since the gate fires right before.
    // =============================================

    __forceinline void Gate() {
        if (IsDebuggerAttached()) {
            ISYSCALL(NtTerminateProcess)((HANDLE)-1, (NTSTATUS)0xDEAD);
        }
    }

} // namespace AntiDebug
