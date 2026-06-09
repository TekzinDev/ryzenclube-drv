#pragma once

// WorkingSetEx CoW detection + PE header integrity
// Depends on: resolve.hpp, remote.hpp, vad.hpp

#define MemorySectionNameInfo  ((MEMORY_INFORMATION_CLASS)2)
#define MemoryWorkingSetExInfo ((MEMORY_INFORMATION_CLASS)4)

#pragma pack(push, 8)
typedef struct _KERNEL_WSEX_INFO {
    PVOID VirtualAddress;
    union {
        ULONG_PTR Flags;
        struct {
            ULONG_PTR Valid           : 1;
            ULONG_PTR ShareCount      : 3;
            ULONG_PTR Win32Protection : 11;
            ULONG_PTR Shared          : 1;
            ULONG_PTR Node            : 6;
            ULONG_PTR Locked          : 1;
            ULONG_PTR LargePage       : 1;
            ULONG_PTR Reserved        : 7;
            ULONG_PTR Bad             : 1;
            ULONG_PTR ReservedUlong   : 32;
        };
    } VirtualAttributes;
} KERNEL_WSEX_INFO;
#pragma pack(pop)

static void CheckMemoryIntegrity(HANDLE hProcess, PEPROCESS Process, PVOID moduleBase, DEEP_TARGET* Target) {
    UCHAR hdrBuf[2048];
    RtlZeroMemory(hdrBuf, sizeof(hdrBuf));

    if (!NT_SUCCESS(SafeReadRemote(Process, moduleBase, hdrBuf, 2048))) {
        Target->Flags |= DEEP_FLAG_PE_TAMPERED;
        return;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdrBuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || (ULONG)dos->e_lfanew > 1024) {
        Target->Flags |= DEEP_FLAG_PE_TAMPERED;
        return;
    }

    PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)(hdrBuf + dos->e_lfanew);
    if (nt64->Signature != IMAGE_NT_SIGNATURE) {
        Target->Flags |= DEEP_FLAG_PE_TAMPERED;
        return;
    }

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt64);
    USHORT numSec = nt64->FileHeader.NumberOfSections;
    if ((ULONG_PTR)(sections + numSec) - (ULONG_PTR)hdrBuf > 2048)
        numSec = (USHORT)(((ULONG_PTR)(hdrBuf + 2048) - (ULONG_PTR)sections) / sizeof(IMAGE_SECTION_HEADER));

    for (USHORT si = 0; si < numSec; si++) {
        ULONG    secChars = sections[si].Characteristics;
        BOOLEAN  isExec   = (secChars & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOLEAN  isWrite  = (secChars & IMAGE_SCN_MEM_WRITE)   != 0;
        BOOLEAN  isRead   = (secChars & IMAGE_SCN_MEM_READ)    != 0;
        BOOLEAN  isRO     = isRead && !isWrite && !isExec;
        BOOLEAN  isText   = isExec && isRead   && !isWrite;

        if ((!isRO && !isText) || sections[si].Misc.VirtualSize == 0) continue;

        ULONG numPages = (sections[si].Misc.VirtualSize + 0xFFF) / 0x1000;

        for (ULONG batch = 0; batch < numPages; batch += 64) {
            ULONG count = numPages - batch;
            if (count > 64) count = 64;

            KERNEL_WSEX_INFO wsInfo[64];
            RtlZeroMemory(wsInfo, sizeof(wsInfo));

            for (ULONG p = 0; p < count; p++) {
                wsInfo[p].VirtualAddress = (PVOID)((ULONG_PTR)moduleBase +
                    sections[si].VirtualAddress + ((batch + p) * 0x1000));
            }

            if (!NT_SUCCESS(g_ZwQueryVirtualMemory(hProcess, NULL, MemoryWorkingSetExInfo,
                wsInfo, count * sizeof(KERNEL_WSEX_INFO), NULL))) continue;

            for (ULONG p = 0; p < count; p++) {
                if (!wsInfo[p].VirtualAttributes.Valid) continue;
                if (isRO) {
                    Target->TotalPages++;
                    if (!wsInfo[p].VirtualAttributes.Shared) Target->PrivatePages++;
                }
                if (isText) {
                    Target->TextTotal++;
                    if (!wsInfo[p].VirtualAttributes.Shared) Target->TextPrivate++;
                }
            }
        }
    }

    if (Target->TotalPages > 0) {
        if ((Target->PrivatePages * 100) / Target->TotalPages >= 50)
            Target->Flags |= DEEP_FLAG_COW_DETECTED;
    }
    if (Target->TextPrivate > 0)
        Target->Flags |= DEEP_FLAG_TEXT_PRIVATE;

    CheckVadControlArea(Process, moduleBase, Target);
}
