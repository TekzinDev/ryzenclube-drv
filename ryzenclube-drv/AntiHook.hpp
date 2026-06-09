#pragma once
#include <windows.h>

#include "XorStr.hpp"
#include "IndirectSyscall.hpp"

// =============================================
//  AntiHook.hpp
//
//  Detect hooks on ntdll functions used by the scanner:
//    1. Inline hooks (byte compare memory vs disk)
//    2. PAGE_GUARD hooks (VEH trap pages)
//    3. Hardware breakpoints (DR0-DR3)
//    4. EAT hooks (AddressOfFunctions/Ordinals tamper)
//
//  ZERO lazy imports — all calls go through ISYSCALL
//  so this check is resistant to usermode hooking even
//  when the process is started suspended.
// =============================================

// NtQueryVirtualMemory info class
#define MemoryBasicInformation 0

namespace AntiHook {

    // =============================================
    //  Get ntdll .text section bounds from PEB
    // =============================================

    struct SectionInfo {
        BYTE* base;
        DWORD size;
        BYTE* ntdllBase;
        DWORD ntdllSize;
    };

    __declspec(noinline) bool GetNtdllTextSection(SectionInfo* out) {
#if defined(_M_X64) || defined(__amd64__)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        auto ldr = *(BYTE**)(peb + 0x18);
        auto first = *(BYTE**)(ldr + 0x10);
        auto second = *(BYTE**)(first);

#if defined(_M_X64) || defined(__amd64__)
        auto ntdll = *(BYTE**)(second + 0x30);
#else
        auto ntdll = *(BYTE**)(second + 0x18);
#endif

        if (!ntdll || ntdll[0] != 'M' || ntdll[1] != 'Z')
            return false;

        auto dosHdr = (IMAGE_DOS_HEADER*)ntdll;
        auto ntHdr = (IMAGE_NT_HEADERS*)(ntdll + dosHdr->e_lfanew);

        out->ntdllBase = ntdll;
        out->ntdllSize = ntHdr->OptionalHeader.SizeOfImage;

        auto sec = IMAGE_FIRST_SECTION(ntHdr);
        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                out->base = ntdll + sec[i].VirtualAddress;
                out->size = sec[i].Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    // =============================================
    //  Get kernel32 base from PEB
    //  InLoadOrderModuleList: [0]=exe [1]=ntdll [2]=kernel32
    // =============================================

    __declspec(noinline) BYTE* GetKernel32Base() {
#if defined(_M_X64) || defined(__amd64__)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        auto ldr = *(BYTE**)(peb + 0x18);
        auto first = *(BYTE**)(ldr + 0x10);   // exe
        auto second = *(BYTE**)(first);        // ntdll
        auto third = *(BYTE**)(second);        // kernel32

#if defined(_M_X64) || defined(__amd64__)
        auto base = *(BYTE**)(third + 0x30);
#else
        auto base = *(BYTE**)(third + 0x18);
#endif
        if (!base || base[0] != 'M' || base[1] != 'Z')
            return nullptr;
        return base;
    }

    // =============================================
    //  Helper: map a DLL from disk as SEC_IMAGE
    //  All syscalls — no kernel32/lazy import dependency
    // =============================================

    __declspec(noinline) BYTE* MapModuleFromDisk(
        const wchar_t* xorPath, HANDLE* outSection, HANDLE* outFile)
    {
        wchar_t pathBuf[256];
        MY_UNICODE_STRING filePath;
        MY_OBJECT_ATTRIBUTES oa;

        size_t k = 0;
        while (xorPath[k] && k < 255) { pathBuf[k] = xorPath[k]; k++; }
        pathBuf[k] = 0;

        filePath.Buffer = pathBuf;
        filePath.Length = (USHORT)(k * sizeof(wchar_t));
        filePath.MaximumLength = (USHORT)(256 * sizeof(wchar_t));

        oa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        oa.RootDirectory = NULL;
        oa.ObjectName = &filePath;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = NULL;
        oa.SecurityQualityOfService = NULL;

        HANDLE hFile = NULL;
        MY_IO_STATUS_BLOCK iosb = { 0 };

        NTSTATUS st = ISYSCALL(NtOpenFile)(
            &hFile,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa, &iosb, FILE_SHARE_READ,
            0x00000020 | 0x00000004);

        if (!NT_SUCCESS(st))
            return nullptr;

        HANDLE hSection = NULL;
        st = ISYSCALL(NtCreateSection)(
            &hSection,
            (ACCESS_MASK)0x0004,           // SECTION_MAP_READ
            (MY_OBJECT_ATTRIBUTES*)NULL,
            (PLARGE_INTEGER)NULL,
            (ULONG)PAGE_READONLY,
            (ULONG)SEC_IMAGE,
            hFile);

        if (!NT_SUCCESS(st)) {
            ISYSCALL(NtClose)(hFile);
            return nullptr;
        }

        BYTE* mapped = NULL;
        SIZE_T viewSize = 0;
        st = ISYSCALL(NtMapViewOfSection)(
            hSection,
            (HANDLE)-1,
            (PVOID*)&mapped,
            (ULONG_PTR)0,
            (SIZE_T)0,
            (PLARGE_INTEGER)NULL,
            &viewSize,
            (ULONG)1,                     // ViewShare
            (ULONG)0,
            (ULONG)PAGE_READONLY);

        if (!NT_SUCCESS(st)) {
            ISYSCALL(NtClose)(hSection);
            ISYSCALL(NtClose)(hFile);
            return nullptr;
        }

        *outSection = hSection;
        *outFile = hFile;
        return mapped;
    }

    __forceinline void UnmapModule(BYTE* mapped, HANDLE hSection, HANDLE hFile) {
        ISYSCALL(NtUnmapViewOfSection)((HANDLE)-1, (PVOID)mapped);
        ISYSCALL(NtClose)(hSection);
        ISYSCALL(NtClose)(hFile);
    }

    // =============================================
    //  1. Inline hook detection — compare .text vs disk
    // =============================================

    // Resolve nearest export name for a given RVA in ntdll
    __declspec(noinline) const char* ResolveExportName(BYTE* ntdllBase, DWORD rva) {
        auto dos = (IMAGE_DOS_HEADER*)ntdllBase;
        auto nt = (IMAGE_NT_HEADERS*)(ntdllBase + dos->e_lfanew);
        auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir.VirtualAddress) return nullptr;

        auto exp = (IMAGE_EXPORT_DIRECTORY*)(ntdllBase + expDir.VirtualAddress);
        auto names = (DWORD*)(ntdllBase + exp->AddressOfNames);
        auto funcs = (DWORD*)(ntdllBase + exp->AddressOfFunctions);
        auto ords  = (WORD*)(ntdllBase + exp->AddressOfNameOrdinals);

        const char* best = nullptr;
        DWORD bestRva = 0;

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            DWORD funcRva = funcs[ords[i]];
            if (funcRva <= rva && funcRva > bestRva) {
                bestRva = funcRva;
                best = (const char*)(ntdllBase + names[i]);
            }
        }
        return best;
    }

    __declspec(noinline) bool CheckInlineHooks() {
        SectionInfo si = { 0 };
        if (!GetNtdllTextSection(&si))
            return false;

        HANDLE hSection = NULL, hFile = NULL;
        BYTE* diskNtdll = MapModuleFromDisk(
            xorstr_(L"\\??\\C:\\Windows\\System32\\ntdll.dll"),
            &hSection, &hFile);

        if (!diskNtdll)
            return false;

        auto diskDos = (IMAGE_DOS_HEADER*)diskNtdll;
        auto diskNt = (IMAGE_NT_HEADERS*)(diskNtdll + diskDos->e_lfanew);
        auto diskSec = IMAGE_FIRST_SECTION(diskNt);

        BYTE* diskText = NULL;
        DWORD diskTextSize = 0;

        for (WORD i = 0; i < diskNt->FileHeader.NumberOfSections; i++) {
            if (diskSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                diskText = diskNtdll + diskSec[i].VirtualAddress;
                diskTextSize = diskSec[i].Misc.VirtualSize;
                break;
            }
        }

        bool hooked = false;

        if (diskText && diskTextSize == si.size) {
            for (DWORD i = 0; i < si.size; i++) {
                if (si.base[i] != diskText[i]) {
                    // Check if this is a VMP hook we should ignore
                    DWORD rva = (DWORD)(si.base + i - si.ntdllBase);
                    const char* funcName = ResolveExportName(si.ntdllBase, rva);
                    bool isVmpHook = false;
                    if (funcName) {
                        // DbgUiRemoteBreakin — VMP anti-debug
                        // NtProtectVirtualMemory — VMP anti-tamper
                        DWORD h = Syscall::HashRuntime(funcName);
                        constexpr DWORD H_DbgUiRemoteBreakin = Syscall::Hash("DbgUiRemoteBreakin");
                        constexpr DWORD H_NtProtectVM = Syscall::Hash("NtProtectVirtualMemory");
                        if (h == H_DbgUiRemoteBreakin || h == H_NtProtectVM)
                            isVmpHook = true;
                    }
                    if (isVmpHook) {
                        i = ((i / 0x20) + 1) * 0x20 - 1;
                        continue;
                    }

                    hooked = true;
                    break;
                }
            }
        }

        UnmapModule(diskNtdll, hSection, hFile);
        return hooked;
    }

    // =============================================
    //  2. PAGE_GUARD detection
    //  Uses NtQueryVirtualMemory via ISYSCALL.
    // =============================================

    __declspec(noinline) bool CheckPageGuardHooks() {
        SectionInfo si = { 0 };
        if (!GetNtdllTextSection(&si))
            return false;

        MEMORY_BASIC_INFORMATION mbi;
        BYTE* addr = si.base;
        BYTE* end = si.base + si.size;

        while (addr < end) {
            SIZE_T retLen = 0;
            NTSTATUS st = ISYSCALL(NtQueryVirtualMemory)(
                (HANDLE)-1,
                (PVOID)addr,
                (ULONG)MemoryBasicInformation,
                (PVOID)&mbi,
                (SIZE_T)sizeof(mbi),
                &retLen);

            if (!NT_SUCCESS(st))
                break;

            if (mbi.Protect & PAGE_GUARD)
                return true;

            if (mbi.State == MEM_COMMIT) {
                DWORD prot = mbi.Protect & 0xFF;
                if (prot == PAGE_EXECUTE_READWRITE ||
                    prot == PAGE_READWRITE) {
                    return true;
                }
            }

            addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        }

        return false;
    }

    // =============================================
    //  3. Hardware breakpoint detection (DR0-DR3)
    //  Uses NtGetContextThread via ISYSCALL.
    // =============================================

    __declspec(noinline) bool CheckHardwareBreakpoints() {
        SectionInfo si = { 0 };
        if (!GetNtdllTextSection(&si))
            return false;

        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        NTSTATUS st = ISYSCALL(NtGetContextThread)((HANDLE)-2, &ctx);
        if (!NT_SUCCESS(st))
            return false;

        DWORD64 dr7 = ctx.Dr7;

        uintptr_t ntStart = (uintptr_t)si.ntdllBase;
        uintptr_t ntEnd = ntStart + si.ntdllSize;

        uintptr_t drs[4] = {
            (uintptr_t)ctx.Dr0,
            (uintptr_t)ctx.Dr1,
            (uintptr_t)ctx.Dr2,
            (uintptr_t)ctx.Dr3
        };

        for (int i = 0; i < 4; i++) {
            if (!(dr7 & (1ULL << (i * 2))))
                continue;

            if (drs[i] >= ntStart && drs[i] < ntEnd)
                return true;

#if defined(_M_X64) || defined(__amd64__)
            auto myPeb = (BYTE*)__readgsqword(0x60);
#else
            auto myPeb = (BYTE*)__readfsdword(0x30);
#endif
            auto myLdr = *(BYTE**)(myPeb + 0x18);
            auto myFirst = *(BYTE**)(myLdr + 0x10);
#if defined(_M_X64) || defined(__amd64__)
            auto myBase = (uintptr_t)*(BYTE**)(myFirst + 0x30);
            auto mySize = (uintptr_t)*(DWORD*)(myFirst + 0x40);
#else
            auto myBase = (uintptr_t)*(BYTE**)(myFirst + 0x18);
            auto mySize = (uintptr_t)*(DWORD*)(myFirst + 0x20);
#endif

            if (drs[i] >= myBase && drs[i] < myBase + mySize)
                return true;
        }

        return false;
    }

    // =============================================
    //  4. EAT hook detection
    //
    //  Compare AddressOfFunctions + AddressOfNameOrdinals
    //  between in-memory and on-disk copies.
    //  Any mismatch = EAT has been patched.
    //
    //  Checks ntdll + kernel32 — the two modules the
    //  lazy importer resolves most APIs from.
    // =============================================

    __declspec(noinline) bool IsEATTampered(BYTE* memBase, BYTE* diskBase) {
        if (!memBase || !diskBase) return false;
        if (memBase[0] != 'M' || diskBase[0] != 'M') return false;

        auto memDos  = (IMAGE_DOS_HEADER*)memBase;
        auto memNt   = (IMAGE_NT_HEADERS*)(memBase + memDos->e_lfanew);
        auto& memDir = memNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!memDir.VirtualAddress) return false;

        auto diskDos  = (IMAGE_DOS_HEADER*)diskBase;
        auto diskNt   = (IMAGE_NT_HEADERS*)(diskBase + diskDos->e_lfanew);
        auto& diskDir = diskNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!diskDir.VirtualAddress) return false;

        auto memExp  = (IMAGE_EXPORT_DIRECTORY*)(memBase + memDir.VirtualAddress);
        auto diskExp = (IMAGE_EXPORT_DIRECTORY*)(diskBase + diskDir.VirtualAddress);

        // Structural tampering
        if (memExp->NumberOfFunctions != diskExp->NumberOfFunctions)
            return true;
        if (memExp->NumberOfNames != diskExp->NumberOfNames)
            return true;

        // Compare AddressOfFunctions — main EAT hook target
        // Attacker changes RVA here to redirect function calls
        auto memFuncs  = (DWORD*)(memBase + memExp->AddressOfFunctions);
        auto diskFuncs = (DWORD*)(diskBase + diskExp->AddressOfFunctions);

        for (DWORD i = 0; i < memExp->NumberOfFunctions; i++) {
            if (memFuncs[i] != diskFuncs[i])
                return true;
        }

        // Compare AddressOfNameOrdinals — ordinal remapping attack
        // Attacker swaps ordinals so name X resolves to function Y
        auto memOrds  = (WORD*)(memBase + memExp->AddressOfNameOrdinals);
        auto diskOrds = (WORD*)(diskBase + diskExp->AddressOfNameOrdinals);

        for (DWORD i = 0; i < memExp->NumberOfNames; i++) {
            if (memOrds[i] != diskOrds[i])
                return true;
        }

        // Compare AddressOfNames — name pointer tampering
        // Attacker changes name RVAs so hash matching hits wrong export
        auto memNames  = (DWORD*)(memBase + memExp->AddressOfNames);
        auto diskNames = (DWORD*)(diskBase + diskExp->AddressOfNames);

        for (DWORD i = 0; i < memExp->NumberOfNames; i++) {
            if (memNames[i] != diskNames[i])
                return true;
        }

        return false;
    }

    __declspec(noinline) bool CheckEATHooks() {
        // --- ntdll EAT ---
        SectionInfo si = { 0 };
        if (GetNtdllTextSection(&si)) {
            HANDLE hSec = NULL, hFile = NULL;
            BYTE* diskNtdll = MapModuleFromDisk(
                xorstr_(L"\\??\\C:\\Windows\\System32\\ntdll.dll"),
                &hSec, &hFile);

            if (diskNtdll) {
                bool tampered = IsEATTampered(si.ntdllBase, diskNtdll);
                UnmapModule(diskNtdll, hSec, hFile);
                if (tampered) return true;
            }
        }

        // --- kernel32 EAT ---
        BYTE* k32Base = GetKernel32Base();
        if (k32Base) {
            HANDLE hSec = NULL, hFile = NULL;
            BYTE* diskK32 = MapModuleFromDisk(
                xorstr_(L"\\??\\C:\\Windows\\System32\\kernel32.dll"),
                &hSec, &hFile);

            if (diskK32) {
                bool tampered = IsEATTampered(k32Base, diskK32);
                UnmapModule(diskK32, hSec, hFile);
                if (tampered) return true;
            }
        }

        return false;
    }

    // =============================================
    //  Combined check
    //  Returns: 0 = clean, bitmask of detections otherwise
    //    bit 0 = inline hook / CoW (.text tamper)
    //    bit 1 = PAGE_GUARD
    //    bit 2 = hardware breakpoint
    //    bit 3 = EAT hook (export table tamper)
    // =============================================

    __declspec(noinline) int Scan() {
        int result = 0;

        if (CheckInlineHooks())
            result |= 1;

        if (CheckPageGuardHooks())
            result |= 2;

        if (CheckHardwareBreakpoints())
            result |= 4;

        if (CheckEATHooks())
            result |= 8;

        return result;
    }

} // namespace AntiHook
