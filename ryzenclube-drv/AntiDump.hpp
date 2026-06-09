#pragma once
#include <windows.h>

#include "XorStr.hpp"
#include "Lazyimporter.hpp"
#include "IndirectSyscall.hpp"

// =============================================
//  AntiDump.hpp
//
//  Full module cloaking:
//    1. Phantom remap ALL modules (EXE + every DLL)
//       NtUnmapViewOfSection + NtAllocateVirtualMemory
//       SEC_IMAGE (MEM_IMAGE) → MEM_PRIVATE in the VAD
//    2. Erase PE headers of our EXE
//    3. Unlink ALL entries from PEB LDR lists
//
//  Result: 0 modules visible in System Informer / Process Hacker
//  NtQueryVirtualMemory returns MEM_PRIVATE for everything
// =============================================

namespace AntiDump {

    // =============================================
    //  Get our own module base from PEB
    // =============================================

    __forceinline BYTE* GetOwnBase() {
#if defined(_M_X64) || defined(__amd64__)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        auto ldr = *(BYTE**)(peb + 0x18);
        auto first = *(BYTE**)(ldr + 0x10);
#if defined(_M_X64) || defined(__amd64__)
        return *(BYTE**)(first + 0x30);
#else
        return *(BYTE**)(first + 0x18);
#endif
    }

    // =============================================
    //  Self-contained remap shellcode (x64)
    //
    //  Has its own syscall;ret gadget embedded — does NOT
    //  depend on ntdll or any external module. This allows
    //  remapping even ntdll itself.
    //
    //  Parameters (x64 calling convention):
    //    rcx = imageBase
    //    rdx = imageSize
    //    r8  = backupBuffer
    //    r9d = NtUnmapViewOfSection SSN
    //    [rsp+28h] = NtAllocateVirtualMemory SSN
    //
    //  Flow:
    //    1. NtUnmapViewOfSection(-1, imageBase)
    //    2. NtAllocateVirtualMemory(-1, &base, 0, &size,
    //       MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    //    3. rep movsb (copy backup → new allocation)
    //    4. ret
    // =============================================

#if defined(_M_X64) || defined(__amd64__)
    inline constexpr BYTE kRemapShellcode[] = {
        // Embedded syscall;ret gadget (self-contained)
        0xEB, 0x03,                                 // jmp +3 (skip gadget)
        0x0F, 0x05,                                 // syscall
        0xC3,                                       // ret

        // Prologue
        0x53,                                       // push rbx
        0x56,                                       // push rsi
        0x57,                                       // push rdi
        0x55,                                       // push rbp
        0x41, 0x54,                                 // push r12
        0x41, 0x55,                                 // push r13
        0x41, 0x56,                                 // push r14
        0x41, 0x57,                                 // push r15
        0x48, 0x83, 0xEC, 0x60,                     // sub rsp, 0x60

        // r15 = address of embedded gadget (rip-relative)
        0x4C, 0x8D, 0x3D, 0xE6, 0xFF, 0xFF, 0xFF,  // lea r15, [rip - 26]

        // Save parameters
        0x4C, 0x8B, 0xE1,                           // mov r12, rcx   (imageBase)
        0x4C, 0x8B, 0xEA,                           // mov r13, rdx   (imageSize)
        0x4D, 0x8B, 0xF0,                           // mov r14, r8    (backupBuffer)
        0x41, 0x8B, 0xD9,                           // mov ebx, r9d   (ssnUnmap)
        // ssnAlloc: 8 pushes(0x40) + sub 0x60 = 0xA0; + 0x28 = 0xC8
        0x8B, 0xAC, 0x24, 0xC8, 0x00, 0x00, 0x00,  // mov ebp, [rsp+0xC8]

        // --- NtUnmapViewOfSection(NtCurrentProcess(), imageBase) ---
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rcx, -1
        0x4C, 0x89, 0xE2,                           // mov rdx, r12
        0x4C, 0x8B, 0xD1,                           // mov r10, rcx
        0x8B, 0xC3,                                 // mov eax, ebx
        0x41, 0xFF, 0xD7,                           // call r15

        // --- NtAllocateVirtualMemory ---
        0x4C, 0x89, 0x64, 0x24, 0x50,               // mov [rsp+0x50], r12
        0x4C, 0x89, 0x6C, 0x24, 0x58,               // mov [rsp+0x58], r13
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,  // mov rcx, -1
        0x48, 0x8D, 0x54, 0x24, 0x50,               // lea rdx, [rsp+0x50]
        0x4D, 0x31, 0xC0,                           // xor r8, r8
        0x4C, 0x8D, 0x4C, 0x24, 0x58,               // lea r9, [rsp+0x58]
        0xC7, 0x44, 0x24, 0x20, 0x00, 0x30, 0x00, 0x00, // mov [rsp+0x20], 0x3000
        0xC7, 0x44, 0x24, 0x28, 0x40, 0x00, 0x00, 0x00, // mov [rsp+0x28], 0x40
        0x4C, 0x8B, 0xD1,                           // mov r10, rcx
        0x8B, 0xC5,                                 // mov eax, ebp
        0x41, 0xFF, 0xD7,                           // call r15

        // --- memcpy(imageBase, backupBuffer, imageSize) ---
        0x4C, 0x89, 0xE7,                           // mov rdi, r12
        0x4C, 0x89, 0xF6,                           // mov rsi, r14
        0x4C, 0x89, 0xE9,                           // mov rcx, r13
        0xFC,                                       // cld
        0xF3, 0xA4,                                 // rep movsb

        // Epilogue
        0x48, 0x83, 0xC4, 0x60,                     // add rsp, 0x60
        0x41, 0x5F,                                 // pop r15
        0x41, 0x5E,                                 // pop r14
        0x41, 0x5D,                                 // pop r13
        0x41, 0x5C,                                 // pop r12
        0x5D,                                       // pop rbp
        0x5F,                                       // pop rdi
        0x5E,                                       // pop rsi
        0x5B,                                       // pop rbx
        0xC3,                                       // ret
    };
#endif

    // =============================================
    //  Phantom Remap ALL modules
    //
    //  Walks PEB→Ldr→InLoadOrderModuleList,
    //  collects every loaded module (EXE + DLLs),
    //  then remaps each one from MEM_IMAGE → MEM_PRIVATE.
    //
    //  After this, NtQueryVirtualMemory returns MEM_PRIVATE
    //  for ALL module regions. System Informer's
    //  PhpEnumGenericMappedFilesAndImages finds nothing.
    // =============================================

    __declspec(noinline) bool PhantomRemapAll() {
#if defined(_M_X64) || defined(__amd64__)
        // --- 1. Collect all modules from PEB ---
        auto peb = (BYTE*)__readgsqword(0x60);
        auto ldr = *(BYTE**)(peb + 0x18);
        BYTE* listHead = ldr + 0x10;  // &InLoadOrderModuleList

        struct ModInfo { BYTE* base; SIZE_T size; };
        ModInfo modules[128];
        int modCount = 0;

        BYTE* cur = *(BYTE**)(listHead);  // first entry Flink
        while (cur != listHead && modCount < 128) {
            BYTE* dllBase = *(BYTE**)(cur + 0x30);
            DWORD dllSize = *(DWORD*)(cur + 0x40);
            if (dllBase && dllSize) {
                modules[modCount].base = dllBase;
                modules[modCount].size = (SIZE_T)dllSize;
                modCount++;
            }
            cur = *(BYTE**)cur;  // follow Flink
        }

        if (modCount == 0)
            return false;

        // ntdll cannot be remapped — it contains the exception dispatcher,
        // critical section implementation, and loader internals.
        // It's present in every Windows process so it's not suspicious.
        BYTE* ntdllBase = Syscall::GetNtdllBase();

        // --- 2. Resolve SSNs ---
        DWORD ssnUnmap = Syscall::GetSsn(Syscall::H_NtUnmapViewOfSection);
        DWORD ssnAlloc = Syscall::GetSsn(Syscall::H_NtAllocateVirtualMemory);
        if (!ssnUnmap || !ssnAlloc)
            return false;

        // --- 3. Prepare shellcode buffer (one buffer, reused for all) ---
        BYTE* scBuf = (BYTE*)lzimpLI_FN(VirtualAlloc)(
            (LPVOID)nullptr, (SIZE_T)0x1000,
            (DWORD)(MEM_COMMIT | MEM_RESERVE), (DWORD)PAGE_EXECUTE_READWRITE);
        if (!scBuf)
            return false;

        for (DWORD i = 0; i < sizeof(kRemapShellcode); i++)
            scBuf[i] = kRemapShellcode[i];

        typedef void (*RemapFn)(PVOID, SIZE_T, PVOID, DWORD, DWORD);
        auto fn = (RemapFn)scBuf;

        // --- 4. Remap each module (skip ntdll) ---
        for (int i = 0; i < modCount; i++) {
            BYTE* base = modules[i].base;
            SIZE_T size = modules[i].size;

            // Skip ntdll — cannot be safely remapped
            if (base == ntdllBase)
                continue;

            // Allocate backup
            BYTE* backup = (BYTE*)lzimpLI_FN(VirtualAlloc)(
                (LPVOID)nullptr, size,
                (DWORD)(MEM_COMMIT | MEM_RESERVE), (DWORD)PAGE_READWRITE);
            if (!backup)
                continue;

            // Copy module to backup
            for (SIZE_T j = 0; j < size; j++)
                ((volatile BYTE*)backup)[j] = ((volatile BYTE*)base)[j];

            // Shellcode: unmap → alloc private → copy back
            fn(base, size, backup, ssnUnmap, ssnAlloc);

            // Free backup
            lzimpLI_FN(VirtualFree)((LPVOID)backup, (SIZE_T)0, (DWORD)MEM_RELEASE);
        }

        // Free shellcode buffer
        lzimpLI_FN(VirtualFree)((LPVOID)scBuf, (SIZE_T)0, (DWORD)MEM_RELEASE);

        return true;
#else
        return false;
#endif
    }

    // =============================================
    //  Erase PE headers from memory
    // =============================================

    __declspec(noinline) bool EraseHeaders() {
        BYTE* base = GetOwnBase();
        if (!base)
            return false;

        auto dosHdr = (IMAGE_DOS_HEADER*)base;
        if (dosHdr->e_magic != 0x5A4D)
            return false;

        auto ntHdr = (IMAGE_NT_HEADERS*)(base + dosHdr->e_lfanew);
        DWORD headerSize = ntHdr->OptionalHeader.SizeOfHeaders;

        // After PhantomRemap, memory is PAGE_EXECUTE_READWRITE
        // VirtualProtect just in case
        DWORD oldProtect = 0;
        lzimpLI_FN(VirtualProtect)(
            (LPVOID)base, (SIZE_T)headerSize, (DWORD)PAGE_READWRITE, &oldProtect);

        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            ntHdr->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
            ntHdr->OptionalHeader.DataDirectory[i].Size = 0;
        }

        volatile BYTE* p = (volatile BYTE*)base;
        for (DWORD i = 0; i < headerSize; i++)
            p[i] = 0;

        return true;
    }

    // =============================================
    //  Unlink a LIST_ENTRY node from its list
    // =============================================

    __forceinline void UnlinkListEntry(BYTE* entry, DWORD offset) {
        BYTE** flink = (BYTE**)(entry + offset);
        BYTE** blink = (BYTE**)(entry + offset + sizeof(PVOID));
        if (*flink && *blink && *flink != (BYTE*)(entry + offset)) {
            *(BYTE**)(*blink + 0x00) = *flink;
            *(BYTE**)(*flink + sizeof(PVOID)) = *blink;
            *flink = (BYTE*)(entry + offset);
            *blink = (BYTE*)(entry + offset);
        }
    }

    // =============================================
    //  Unlink ALL modules from PEB LDR lists
    //
    //  Walks InLoadOrderModuleList and for each entry:
    //    - Unlinks HashLinks (LdrpHashTable)
    //    - Zeros module name strings
    //  Then empties all 3 list heads.
    //
    //  Result: PEB shows 0 loaded modules.
    // =============================================

    __declspec(noinline) void UnlinkAllFromPEB() {
#if defined(_M_X64) || defined(__amd64__)
        auto peb = (BYTE*)__readgsqword(0x60);
#else
        auto peb = (BYTE*)__readfsdword(0x30);
#endif
        auto ldr = *(BYTE**)(peb + 0x18);

        // Empty all 3 list heads (set Flink = Blink = &Head)
        // This makes PEB report 0 loaded modules.
        // We don't walk/zero individual entries — just disconnect the heads.
        // System Informer walks InLoadOrderModuleList and finds nothing.

        // InLoadOrderModuleList (+0x10)
        *(BYTE**)(ldr + 0x10) = ldr + 0x10;
        *(BYTE**)(ldr + 0x18) = ldr + 0x10;

        // InMemoryOrderModuleList (+0x20)
        *(BYTE**)(ldr + 0x20) = ldr + 0x20;
        *(BYTE**)(ldr + 0x28) = ldr + 0x20;

        // InInitializationOrderModuleList (+0x30)
        *(BYTE**)(ldr + 0x30) = ldr + 0x30;
        *(BYTE**)(ldr + 0x38) = ldr + 0x30;

        // =============================================
        //  Zero PEB fields that leak the image base
        //
        //  Scylla reads PEB->ImageBaseAddress directly —
        //  doesn't need LDR lists at all.
        //
        //  PEB layout (x64):
        //    +0x10  ImageBaseAddress    ← Scylla primary source
        //    +0x20  ProcessParameters   ← contains ImagePathName
        //
        //  We zero ImageBaseAddress to kill Scylla's
        //  "Attach to process" → automatic base detection.
        //  Also poison ProcessParameters->ImagePathName
        //  so remote PEB reads can't recover the exe path.
        // =============================================

        // Zero PEB->ImageBaseAddress (+0x10)
        *(PVOID*)(peb + 0x10) = NULL;

        // Poison ProcessParameters->ImagePathName
        // ProcessParameters at PEB+0x20
        auto params = *(BYTE**)(peb + 0x20);
        if (params) {
            // RTL_USER_PROCESS_PARAMETERS->ImagePathName
            // is a UNICODE_STRING at offset 0x60 on x64
            // Length at +0x60, MaximumLength at +0x62, Buffer at +0x68
#if defined(_M_X64) || defined(__amd64__)
            *(USHORT*)(params + 0x60) = 0;  // Length = 0
            wchar_t* imgBuf = *(wchar_t**)(params + 0x68);
            if (imgBuf) {
                // Zero the path string in-place
                for (int i = 0; i < 260 && imgBuf[i]; i++)
                    imgBuf[i] = 0;
            }
#else
            *(USHORT*)(params + 0x38) = 0;
            wchar_t* imgBuf = *(wchar_t**)(params + 0x3C);
            if (imgBuf) {
                for (int i = 0; i < 260 && imgBuf[i]; i++)
                    imgBuf[i] = 0;
            }
#endif
        }
    }

    // =============================================
    //  Xorshift128+ PRNG — fast, high-entropy, zero CRT
    //  Seeded from RDTSC + stack address for uniqueness
    // =============================================

    struct Xorshift128 {
        unsigned __int64 s0, s1;

        __forceinline void seed() {
            s0 = __rdtsc();
            s1 = s0 ^ ((unsigned __int64)(void*)&s0);
            // Warm up — discard first 16 outputs
            for (int i = 0; i < 16; i++) next();
        }

        __forceinline unsigned __int64 next() {
            unsigned __int64 x = s0;
            unsigned __int64 y = s1;
            s0 = y;
            x ^= x << 23;
            x ^= x >> 17;
            x ^= y ^ (y >> 26);
            s1 = x;
            return x + y;
        }
    };

    // =============================================
    //  Build a fake PE header that looks realistic
    //
    //  Creates: MZ → DOS stub → PE signature → COFF header
    //  → OptionalHeader → 4-5 section headers
    //  Total ~0x400 bytes, rest filled with entropy
    //
    //  PE reconstruction tools (Scylla, pe-sieve, etc.)
    //  will parse these as valid modules and waste time.
    // =============================================

    __declspec(noinline) void BuildFakePE(BYTE* buf, SIZE_T totalSize, Xorshift128* rng) {
        // Zero the header area first
        for (int i = 0; i < 0x400 && i < (int)totalSize; i++)
            buf[i] = 0;

        // DOS header
        auto dos = (IMAGE_DOS_HEADER*)buf;
        dos->e_magic = 0x5A4D;  // MZ
        dos->e_cblp = (WORD)(rng->next() & 0xFF);
        dos->e_cp = (WORD)(rng->next() % 8 + 1);
        dos->e_cparhdr = 4;
        dos->e_minalloc = 0x10;
        dos->e_maxalloc = 0xFFFF;
        dos->e_sp = 0xB8;
        dos->e_lfarlc = 0x40;
        dos->e_lfanew = 0x100;  // PE header at offset 0x100

        // DOS stub — "This program cannot be run in DOS mode" equivalent
        // Fill with realistic-looking DOS stub bytes
        for (int i = 0x40; i < 0x100; i++)
            buf[i] = (BYTE)(rng->next() & 0xFF);
        // Make it look like a real DOS stub
        buf[0x40] = 0x0E; buf[0x41] = 0x1F; buf[0x42] = 0xBA;
        buf[0x4E] = 0xB4; buf[0x4F] = 0x09; buf[0x50] = 0xCD; buf[0x51] = 0x21;

        // PE signature
        *(DWORD*)(buf + 0x100) = 0x00004550;  // "PE\0\0"

        // COFF header
        auto coff = (IMAGE_FILE_HEADER*)(buf + 0x104);
        coff->Machine = IMAGE_FILE_MACHINE_AMD64;
        coff->NumberOfSections = 4 + (WORD)(rng->next() % 2);  // 4 or 5 sections
        coff->TimeDateStamp = (DWORD)(0x60000000 + (rng->next() % 0x5000000)); // realistic timestamp
        coff->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        coff->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;

        // Optional header (x64)
        auto opt = (IMAGE_OPTIONAL_HEADER64*)(buf + 0x104 + sizeof(IMAGE_FILE_HEADER));
        opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        opt->MajorLinkerVersion = 14;
        opt->MinorLinkerVersion = (BYTE)(rng->next() % 40);
        opt->SizeOfCode = (DWORD)(totalSize / 2) & ~0xFFF;
        opt->SizeOfInitializedData = (DWORD)(totalSize / 4) & ~0xFFF;
        opt->AddressOfEntryPoint = 0x1000 + (DWORD)(rng->next() % 0x1000);
        opt->BaseOfCode = 0x1000;
        opt->ImageBase = 0x180000000ULL + (rng->next() % 0x40000000ULL);
        opt->SectionAlignment = 0x1000;
        opt->FileAlignment = 0x200;
        opt->MajorOperatingSystemVersion = 10;
        opt->MajorSubsystemVersion = 6;
        opt->SizeOfImage = (DWORD)totalSize;
        opt->SizeOfHeaders = 0x400;
        opt->CheckSum = (DWORD)(rng->next());
        opt->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
        opt->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                  IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                  IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
        opt->SizeOfStackReserve = 0x100000;
        opt->SizeOfStackCommit = 0x1000;
        opt->SizeOfHeapReserve = 0x100000;
        opt->SizeOfHeapCommit = 0x1000;
        opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

        // Fake data directories — export + import + reloc
        opt->DataDirectory[0].VirtualAddress = 0x1000 + (DWORD)(rng->next() % 0x800);
        opt->DataDirectory[0].Size = (DWORD)(rng->next() % 0x200 + 0x40);
        opt->DataDirectory[1].VirtualAddress = 0x2000 + (DWORD)(rng->next() % 0x400);
        opt->DataDirectory[1].Size = (DWORD)(rng->next() % 0x100 + 0x28);
        opt->DataDirectory[5].VirtualAddress = (DWORD)(totalSize - 0x2000);
        opt->DataDirectory[5].Size = (DWORD)(rng->next() % 0x1000 + 0x100);

        // Section headers
        WORD numSec = coff->NumberOfSections;
        auto sec = IMAGE_FIRST_SECTION(
            (IMAGE_NT_HEADERS*)(buf + 0x100));

        // Section name templates
        const char* secNames[] = { ".text", ".rdata", ".data", ".rsrc", ".reloc" };
        DWORD secChars[] = {
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA,
        };

        DWORD secVA = 0x1000;
        for (WORD s = 0; s < numSec && s < 5; s++) {
            // Copy section name
            for (int c = 0; c < 8; c++) sec[s].Name[c] = 0;
            const char* nm = secNames[s];
            for (int c = 0; nm[c] && c < 8; c++) sec[s].Name[c] = nm[c];

            DWORD secSize = (DWORD)((totalSize / (numSec + 1)) & ~0xFFF);
            if (secSize < 0x1000) secSize = 0x1000;

            sec[s].VirtualAddress = secVA;
            sec[s].Misc.VirtualSize = secSize - (DWORD)(rng->next() % 0x100);
            sec[s].SizeOfRawData = secSize;
            sec[s].PointerToRawData = secVA;  // SEC_IMAGE layout
            sec[s].Characteristics = secChars[s];

            secVA += secSize;
        }
    }

    // =============================================
    //  Flood memory with decoy MEM_PRIVATE regions
    //
    //  Creates 24 decoy allocations:
    //    - Sizes 512KB to 4MB (randomized)
    //    - Each has a valid-looking PE header
    //    - Body filled with high-entropy random data
    //    - All MEM_PRIVATE — identical to phantom-remapped modules
    //
    //  Effect on dump:
    //    - Dump goes from ~50MB to ~100MB+
    //    - PE scanners find 24+ fake "modules"
    //    - Impossible to tell which MEM_PRIVATE regions are real
    //    - Manual analysis is a nightmare
    //
    //  Called AFTER PhantomRemapAll so decoys blend in.
    // =============================================

    __declspec(noinline) void FloodDecoys() {
        Xorshift128 rng;
        rng.seed();

        constexpr int NUM_DECOYS = 24;

        for (int d = 0; d < NUM_DECOYS; d++) {
            // Random size: 512KB to 4MB, page-aligned
            SIZE_T size = ((rng.next() % (3 * 1024 * 1024)) + (512 * 1024)) & ~0xFFFULL;

            BYTE* block = NULL;
            NTSTATUS st = ISYSCALL(NtAllocateVirtualMemory)(
                (HANDLE)-1, (PVOID*)&block, (ULONG_PTR)0,
                &size, (ULONG)0x3000, (ULONG)PAGE_READWRITE);

            if (!NT_SUCCESS(st) || !block)
                continue;

            // Build fake PE header
            BuildFakePE(block, size, &rng);

            // Fill body (after header) with high-entropy random data
            // Write in 8-byte chunks for speed
            unsigned __int64* p64 = (unsigned __int64*)(block + 0x400);
            SIZE_T remaining = (size - 0x400) / 8;

            for (SIZE_T i = 0; i < remaining; i++)
                p64[i] = rng.next();

            // Sprinkle realistic x86-64 instruction patterns into .text area
            // to fool disassemblers analyzing the dump
            BYTE* textStart = block + 0x1000;
            SIZE_T textEnd = size / 2;
            if (textEnd > size - 0x1000) textEnd = size - 0x1000;

            for (SIZE_T off = 0; off < textEnd - 0x1000; off += 0x20 + (rng.next() % 0x40)) {
                BYTE* spot = textStart + off;
                // Common function prologue patterns
                switch (rng.next() % 6) {
                    case 0: // push rbp; mov rbp, rsp; sub rsp, XX
                        spot[0] = 0x55; spot[1] = 0x48; spot[2] = 0x89;
                        spot[3] = 0xE5; spot[4] = 0x48; spot[5] = 0x83;
                        spot[6] = 0xEC; spot[7] = (BYTE)(0x20 + (rng.next() % 0x60));
                        break;
                    case 1: // sub rsp, XX; mov [rsp+...], ...
                        spot[0] = 0x48; spot[1] = 0x83; spot[2] = 0xEC;
                        spot[3] = (BYTE)(0x28 + (rng.next() % 0x40));
                        spot[4] = 0x48; spot[5] = 0x89; spot[6] = 0x4C;
                        spot[7] = 0x24; spot[8] = 0x08;
                        break;
                    case 2: // mov rax, [rcx+XX]; test rax,rax; jz
                        spot[0] = 0x48; spot[1] = 0x8B; spot[2] = 0x41;
                        spot[3] = (BYTE)(rng.next() % 0x40);
                        spot[4] = 0x48; spot[5] = 0x85; spot[6] = 0xC0;
                        spot[7] = 0x74; spot[8] = (BYTE)(rng.next() % 0x20);
                        break;
                    case 3: // xor eax,eax; ret (common stub)
                        spot[0] = 0x33; spot[1] = 0xC0; spot[2] = 0xC3;
                        break;
                    case 4: // lea rcx, [rip+XX]; call [rip+XX]
                        spot[0] = 0x48; spot[1] = 0x8D; spot[2] = 0x0D;
                        *(DWORD*)(spot+3) = (DWORD)(rng.next());
                        spot[7] = 0xFF; spot[8] = 0x15;
                        *(DWORD*)(spot+9) = (DWORD)(rng.next());
                        break;
                    case 5: // mov r10, rcx; mov eax, XX (syscall stub pattern)
                        spot[0] = 0x4C; spot[1] = 0x8B; spot[2] = 0xD1;
                        spot[3] = 0xB8;
                        *(DWORD*)(spot+4) = (DWORD)(rng.next() % 0x200);
                        break;
                }
            }

            // Change protection to match real module pages
            // .text area → PAGE_EXECUTE_READ
            SIZE_T textSize = textEnd;
            PVOID textBase = (PVOID)(block + 0x1000);
            ULONG oldProt = 0;
            ISYSCALL(NtProtectVirtualMemory)(
                (HANDLE)-1, &textBase, &textSize,
                (ULONG)PAGE_EXECUTE_READ, &oldProt);

            // Header area → PAGE_READONLY (like real mapped PE)
            SIZE_T hdrSize = 0x1000;
            PVOID hdrBase = (PVOID)block;
            ISYSCALL(NtProtectVirtualMemory)(
                (HANDLE)-1, &hdrBase, &hdrSize,
                (ULONG)PAGE_READONLY, &oldProt);
        }
    }

    // =============================================
    //  Combined anti-dump — full module cloaking
    //
    //  Order:
    //    1. Phantom remap ALL modules (MEM_IMAGE → MEM_PRIVATE)
    //    2. Erase our EXE's PE headers
    //    3. Empty ALL PEB LDR lists (0 modules)
    // =============================================

    __declspec(noinline) void Init() {
        PhantomRemapAll();
        EraseHeaders();
        UnlinkAllFromPEB();
    }

} // namespace AntiDump
