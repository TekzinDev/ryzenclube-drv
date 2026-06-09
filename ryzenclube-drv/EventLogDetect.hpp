#pragma once
#include <windows.h>

#include "XorStr.hpp"
#include "Lazyimporter.hpp"
#include "IndirectSyscall.hpp"

// =============================================
//  EventLogDetect.hpp
// =============================================

// SCM constants
#ifndef MY_SC_STATUS_PROCESS_INFO
#define MY_SC_STATUS_PROCESS_INFO 0
#endif

// PROCESS_BASIC_INFORMATION for NtQueryInformationProcess
#ifndef _WINTERNL_
typedef enum _MY_PROCESSINFOCLASS {
    MyProcessBasicInformation = 0
} MY_PROCESSINFOCLASS;

typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;
#endif

// PSAPI_WORKING_SET_EX_INFORMATION
typedef struct _MY_WSEX_INFO {
    PVOID VirtualAddress;
    union {
        ULONG_PTR Flags;
        struct {
            ULONG_PTR Valid : 1;
            ULONG_PTR ShareCount : 3;
            ULONG_PTR Win32Protection : 11;
            ULONG_PTR Shared : 1;
            ULONG_PTR Node : 6;
            ULONG_PTR Locked : 1;
            ULONG_PTR LargePage : 1;
            ULONG_PTR Reserved : 7;
            ULONG_PTR Bad : 1;
#ifdef _M_X64
            ULONG_PTR ReservedUlong : 32;
#endif
        };
    } VirtualAttributes;
} MY_WSEX_INFO;

namespace EventLogDetect {

    // =============================================
    //  Get EventLog service PID from SCM
    // =============================================

    __declspec(noinline) DWORD GetEventLogPID() {
        // advapi32.dll pre-loaded in main before anti-dump
        // (LoadLibraryA after PEB unlink would create a new MEM_IMAGE mapping)

        SC_HANDLE scm = lzimpLI_FN(OpenSCManagerW)(
            (LPCWSTR)NULL, (LPCWSTR)NULL, (DWORD)SC_MANAGER_CONNECT);
        if (!scm) return 0;

        SC_HANDLE svc = lzimpLI_FN(OpenServiceW)(
            scm, xorstr_(L"eventlog"), (DWORD)SERVICE_QUERY_STATUS);
        if (!svc) {
            lzimpLI_FN(CloseServiceHandle)(scm);
            return 0;
        }

        SERVICE_STATUS_PROCESS ssp;
        memset(&ssp, 0, sizeof(ssp));
        DWORD needed = 0;

        BOOL ok = lzimpLI_FN(QueryServiceStatusEx)(
            svc, (SC_STATUS_TYPE)MY_SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp, (DWORD)sizeof(ssp), &needed);

        lzimpLI_FN(CloseServiceHandle)(svc);
        lzimpLI_FN(CloseServiceHandle)(scm);

        return ok ? ssp.dwProcessId : 0;
    }

    // =============================================
    //  Find ntdll base in remote process via NtQueryInformationProcess
    //  + walk PEB->Ldr->InLoadOrderModuleList
    //
    //  Returns ntdll base address in target process
    // =============================================

    __declspec(noinline) PVOID FindRemoteNtdll(HANDLE hProcess) {
        MY_PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;

        NTSTATUS st = ISYSCALL(NtQueryInformationProcess)(
            hProcess, (ULONG)0, &pbi, (ULONG)sizeof(pbi), &retLen);
        if (!NT_SUCCESS(st) || !pbi.PebBaseAddress)
            return NULL;

        // Read PEB->Ldr
        BYTE pebBuf[0x100];
        SIZE_T read = 0;
        if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, pbi.PebBaseAddress, pebBuf, (SIZE_T)sizeof(pebBuf), &read)))
            return NULL;

#ifdef _M_X64
        PVOID ldrAddr = *(PVOID*)(pebBuf + 0x18);
#else
        PVOID ldrAddr = *(PVOID*)(pebBuf + 0x0C);
#endif

        // Read LDR
        BYTE ldrBuf[0x50];
        if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, ldrAddr, ldrBuf, (SIZE_T)sizeof(ldrBuf), &read)))
            return NULL;

        // InLoadOrderModuleList.Flink
#ifdef _M_X64
        PVOID firstEntry = *(PVOID*)(ldrBuf + 0x10);
#else
        PVOID firstEntry = *(PVOID*)(ldrBuf + 0x0C);
#endif

        // Walk list — [0]=exe, [1]=ntdll
        BYTE entryBuf[0x120];
        PVOID current = firstEntry;

        for (int i = 0; i < 3; i++) {
            if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, current, entryBuf, (SIZE_T)sizeof(entryBuf), &read)))
                return NULL;

            if (i == 1) {
                // Second entry = ntdll
#ifdef _M_X64
                return *(PVOID*)(entryBuf + 0x30);  // DllBase
#else
                return *(PVOID*)(entryBuf + 0x18);
#endif
            }

            // Follow Flink
            current = *(PVOID*)(entryBuf);
        }
        return NULL;
    }

    // =============================================
    //  XRC Detect 04: NtWriteFile integrity check
    //
    //  Read NtWriteFile stub from EventLog's ntdll
    //  and compare with our own (clean) copy.
    //  SysmonPatchTool patches the IAT or first bytes
    //  to redirect NtWriteFile → RtlExitUserThread or
    //  patches it to return STATUS_UNSUCCESSFUL.
    //
    //  Also checks NtTraceEvent (ETW session blind)
    // =============================================

    // =============================================
    //  XRC Detect 04: NtWriteFile/NtTraceEvent CoW detection
    //  Check if PAGES containing these stubs are private
    //  Even if patch bytes are restored, CoW page stays private
    // =============================================

    __declspec(noinline) bool CheckNtWriteFileIntegrity() {
        DWORD pid = GetEventLogPID();
        if (!pid) return false;

        HANDLE hProcess = NULL;
        { MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
          MY_OBJECT_ATTRIBUTES poa = { sizeof(MY_OBJECT_ATTRIBUTES), NULL, NULL, 0, NULL, NULL };
          ISYSCALL(NtOpenProcess)(&hProcess, (ACCESS_MASK)(0x0010 | 0x0400), &poa, &cid); }
        if (!hProcess) return false;

        PVOID remoteNtdll = FindRemoteNtdll(hProcess);
        if (!remoteNtdll) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        // Use pre-saved base (PEB LDR lists are empty after anti-dump)
        BYTE* localNtdll = ::g_LocalNtdllBase;

        auto dos = (IMAGE_DOS_HEADER*)localNtdll;
        auto nt = (IMAGE_NT_HEADERS*)(localNtdll + dos->e_lfanew);
        auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        auto exp = (IMAGE_EXPORT_DIRECTORY*)(localNtdll + expDir.VirtualAddress);
        auto names = (DWORD*)(localNtdll + exp->AddressOfNames);
        auto funcs = (DWORD*)(localNtdll + exp->AddressOfFunctions);
        auto ords = (WORD*)(localNtdll + exp->AddressOfNameOrdinals);

        constexpr auto H = [](const char* s) constexpr -> DWORD {
            DWORD h = 5381;
            while (*s) { h = ((h << 5) + h) + (unsigned char)*s; s++; }
            return h;
        };

        struct Target {
            DWORD nameHash;
            DWORD rva;
        };

        Target targets[] = {
            { H("NtWriteFile"),    0 },
            { H("NtTraceEvent"),   0 },
            { H("NtTraceControl"), 0 },
        };
        constexpr int NUM_TARGETS = 3;

        int found = 0;
        for (DWORD i = 0; i < exp->NumberOfNames && found < NUM_TARGETS; i++) {
            const char* name = (const char*)(localNtdll + names[i]);
            if (name[0] != 'N' || name[1] != 't') continue;

            DWORD h = 5381;
            const char* p = name;
            while (*p) { h = ((h << 5) + h) + (unsigned char)*p; p++; }

            for (int t = 0; t < NUM_TARGETS; t++) {
                if (targets[t].rva == 0 && targets[t].nameHash == h) {
                    targets[t].rva = funcs[ords[i]];
                    found++;
                    break;
                }
            }
        }

        // Check if pages containing these functions are private (CoW)
        bool tampered = false;

        for (int t = 0; t < NUM_TARGETS; t++) {
            if (targets[t].rva == 0) continue;

            DWORD pageRva = targets[t].rva & ~0xFFF;
            PVOID remotePage = (BYTE*)remoteNtdll + pageRva;

            MY_WSEX_INFO wsInfo;
            wsInfo.VirtualAddress = remotePage;
            wsInfo.VirtualAttributes.Flags = 0;

            if (NT_SUCCESS(ISYSCALL(NtQueryVirtualMemory)(
                hProcess, (PVOID)NULL, (ULONG)4,
                (PVOID)&wsInfo, (SIZE_T)sizeof(MY_WSEX_INFO), (PSIZE_T)NULL)))
            {
                if (wsInfo.VirtualAttributes.Valid &&
                    !wsInfo.VirtualAttributes.Shared) {
                    tampered = true;
                    break;
                }
            }
        }

        ISYSCALL(NtClose)(hProcess);
        return tampered;
    }

    // =============================================
    //  XRC Detect 05: ntdll unmap/remap detection
    //
    //  After CoW revert (unmap + remap + WriteProcessMemory),
    //  read-only sections (.rdata, .pdata, .rsrc) become
    //  100% private. This NEVER happens normally.
    //
    //  Uses QueryWorkingSetEx on EventLog's ntdll.
    // =============================================

    __declspec(noinline) bool CheckNtdllCoWRevert() {
        DWORD pid = GetEventLogPID();
        if (!pid) return false;

        HANDLE hProcess = NULL;
        { MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
          MY_OBJECT_ATTRIBUTES poa = { sizeof(MY_OBJECT_ATTRIBUTES), NULL, NULL, 0, NULL, NULL };
          ISYSCALL(NtOpenProcess)(&hProcess, (ACCESS_MASK)(0x0010 | 0x0400 | 0x1000), &poa, &cid); }
        if (!hProcess) return false;

        PVOID remoteNtdll = FindRemoteNtdll(hProcess);
        if (!remoteNtdll) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        BYTE* hdrBuf = NULL;
        { SIZE_T allocSz = 2048;
          ISYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, (ULONG_PTR)0, &allocSz, (ULONG)0x3000, (ULONG)0x04); }
        if (!hdrBuf) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        SIZE_T read = 0;
        if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, remoteNtdll, hdrBuf, (SIZE_T)2048, &read))) {
            { SIZE_T freeSz = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, &freeSz, (ULONG)0x8000); };
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        auto dos = (IMAGE_DOS_HEADER*)hdrBuf;
        if (dos->e_magic != 0x5A4D) {
            { SIZE_T freeSz = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, &freeSz, (ULONG)0x8000); };
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        auto ntHdr = (IMAGE_NT_HEADERS*)(hdrBuf + dos->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(ntHdr);
        WORD numSec = ntHdr->FileHeader.NumberOfSections;

        DWORD roTotalPages = 0;
        DWORD roPrivatePages = 0;

        for (WORD s = 0; s < numSec; s++) {
            DWORD chars = sec[s].Characteristics;
            bool isExec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isWrite = (chars & IMAGE_SCN_MEM_WRITE) != 0;
            bool isRead = (chars & IMAGE_SCN_MEM_READ) != 0;
            bool isReadOnly = isRead && !isWrite && !isExec;

            if (!isReadOnly || sec[s].Misc.VirtualSize == 0)
                continue;

            DWORD pageSize = 0x1000;
            DWORD numPages = (sec[s].Misc.VirtualSize + pageSize - 1) / pageSize;

            for (DWORD batch = 0; batch < numPages; batch += 64) {
                DWORD count = numPages - batch;
                if (count > 64) count = 64;

                MY_WSEX_INFO wsInfo[64];
                for (DWORD p = 0; p < count; p++) {
                    wsInfo[p].VirtualAddress =
                        (BYTE*)remoteNtdll + sec[s].VirtualAddress + ((batch + p) * pageSize);
                    wsInfo[p].VirtualAttributes.Flags = 0;
                }

                NTSTATUS wsResult = ISYSCALL(NtQueryVirtualMemory)(
                    hProcess, (PVOID)NULL, (ULONG)4,
                    (PVOID)wsInfo, (SIZE_T)(count * sizeof(MY_WSEX_INFO)), (PSIZE_T)NULL);

                if (!NT_SUCCESS(wsResult))
                    continue;

                for (DWORD p = 0; p < count; p++) {
                    if (wsInfo[p].VirtualAttributes.Valid) {
                        roTotalPages++;
                        if (!wsInfo[p].VirtualAttributes.Shared)
                            roPrivatePages++;
                    }
                }
            }
        }

        ISYSCALL(NtClose)(hProcess);
        { SIZE_T freeSz = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, &freeSz, (ULONG)0x8000); };

        if (roTotalPages == 0) return false;

        double ratio = (double)roPrivatePages / (double)roTotalPages;
        return (ratio >= 0.50);
    }

    // =============================================
    //  Find process by name — NtQuerySystemInformation
    //  SystemProcessInformation (class 5)
    //
    //  Returns PID or 0 if not found.
    //  Zero kernel32 dependency.
    // =============================================

    // SYSTEM_PROCESS_INFORMATION offsets (x64):
    //   0x00: NextEntryOffset (ULONG)
    //   0x38: ImageName (UNICODE_STRING — Length @0x38, Buffer @0x40)
    //   0x50: UniqueProcessId (HANDLE)

    __declspec(noinline) DWORD FindProcessByName(const wchar_t* xorName) {
        // Allocate buffer — start at 256KB, retry if too small
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
                (ULONG)5, (PVOID)buf, (ULONG)allocSz, &retLen);

            if (st == (NTSTATUS)0xC0000004L) {
                // STATUS_INFO_LENGTH_MISMATCH — buffer too small
                SIZE_T freeSz = 0;
                ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &freeSz, (ULONG)0x8000);
                buf = NULL;
                allocSz *= 2;
                continue;
            }
            break;
        }

        if (!buf || !NT_SUCCESS(st)) {
            if (buf) {
                SIZE_T freeSz = 0;
                ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &freeSz, (ULONG)0x8000);
            }
            return 0;
        }

        // Walk linked list of SYSTEM_PROCESS_INFORMATION entries
        DWORD pid = 0;
        BYTE* entry = buf;

        for (;;) {
            ULONG nextOffset = *(ULONG*)(entry + 0x00);

            // ImageName UNICODE_STRING at offset 0x38
            USHORT nameLen = *(USHORT*)(entry + 0x38);
            wchar_t* namePtr = *(wchar_t**)(entry + 0x40);

            if (nameLen > 0 && namePtr) {
                USHORT chars = nameLen / sizeof(wchar_t);
                // namePtr points inside our buffer (kernel copies it there)
                // Safe to compare directly
                bool match = true;
                const wchar_t* target = xorName;
                USHORT i = 0;
                while (i < chars && target[i]) {
                    wchar_t a = namePtr[i];
                    wchar_t b = target[i];
                    // inline tolower
                    if (a >= L'A' && a <= L'Z') a += 32;
                    if (b >= L'A' && b <= L'Z') b += 32;
                    if (a != b) { match = false; break; }
                    i++;
                }
                if (match && i == chars && target[i] == 0) {
                    // UniqueProcessId at offset 0x50
                    pid = (DWORD)(ULONG_PTR)*(HANDLE*)(entry + 0x50);
                    break;
                }
            }

            if (nextOffset == 0) break;
            entry += nextOffset;
        }

        SIZE_T freeSz = 0;
        ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&buf, &freeSz, (ULONG)0x8000);
        return pid;
    }

    // =============================================
    //  Find module base in remote process by name
    //  Walks PEB->Ldr->InLoadOrderModuleList
    // =============================================

    __declspec(noinline) PVOID FindRemoteModule(HANDLE hProcess, const wchar_t* xorModName) {
        MY_PROCESS_BASIC_INFORMATION pbi;
        memset(&pbi, 0, sizeof(pbi));
        ULONG retLen = 0;

        NTSTATUS st = ISYSCALL(NtQueryInformationProcess)(
            hProcess, (ULONG)0, &pbi, (ULONG)sizeof(pbi), &retLen);
        if (!NT_SUCCESS(st) || !pbi.PebBaseAddress)
            return NULL;

        // Read PEB
        BYTE pebBuf[0x80];
        SIZE_T read = 0;
        if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, pbi.PebBaseAddress, pebBuf, (SIZE_T)sizeof(pebBuf), &read)))
            return NULL;

#ifdef _M_X64
        PVOID ldrAddr = *(PVOID*)(pebBuf + 0x18);
#else
        PVOID ldrAddr = *(PVOID*)(pebBuf + 0x0C);
#endif

        BYTE ldrBuf[0x50];
        if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, ldrAddr, ldrBuf, (SIZE_T)sizeof(ldrBuf), &read)))
            return NULL;

#ifdef _M_X64
        PVOID listHead = (BYTE*)ldrAddr + 0x10;
        PVOID current = *(PVOID*)(ldrBuf + 0x10);  // Flink
#else
        PVOID listHead = (BYTE*)ldrAddr + 0x0C;
        PVOID current = *(PVOID*)(ldrBuf + 0x0C);
#endif

        // Walk up to 200 modules
        for (int i = 0; i < 200; i++) {
            if (current == listHead)
                break;

            BYTE entryBuf[0x120];
            if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, current, entryBuf, (SIZE_T)sizeof(entryBuf), &read)))
                break;

            // BaseDllName UNICODE_STRING
#ifdef _M_X64
            USHORT nameLen = *(USHORT*)(entryBuf + 0x58);       // BaseDllName.Length
            PVOID  nameBuf = *(PVOID*)(entryBuf + 0x58 + 8);    // BaseDllName.Buffer
            PVOID  dllBase = *(PVOID*)(entryBuf + 0x30);         // DllBase
#else
            USHORT nameLen = *(USHORT*)(entryBuf + 0x2C);
            PVOID  nameBuf = *(PVOID*)(entryBuf + 0x2C + 4);
            PVOID  dllBase = *(PVOID*)(entryBuf + 0x18);
#endif

            if (nameLen > 0 && nameLen < 520 && nameBuf) {
                wchar_t dllName[260];
                USHORT chars = nameLen / sizeof(wchar_t);
                if (chars >= 260) chars = 259;

                if (NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, nameBuf, dllName, (SIZE_T)(chars * sizeof(wchar_t)), &read))) {
                    dllName[chars] = 0;

                    // Case-insensitive compare
                    if (wicmp(dllName, xorModName) == 0)
                        return dllBase;
                }
            }

            // Follow Flink
            current = *(PVOID*)(entryBuf);
        }

        return NULL;
    }

    // =============================================
    //  HD-Player opengl32.dll CoW Revert Detection
    //
    //  Chams hook glDrawElements in opengl32.dll
    //  Attacker does unmap/remap to clean .text CoW
    //  WriteProcessMemory on R/O sections leaves evidence
    //
    //  Same technique as EventLog ntdll check
    // =============================================

    __declspec(noinline) bool CheckGameRenderIntegrity() {
        DWORD pid = FindProcessByName(xorstr_(L"HD-Player.exe"));
        if (!pid) return false;

        HANDLE hProcess = NULL;
        { MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
          MY_OBJECT_ATTRIBUTES poa = { sizeof(MY_OBJECT_ATTRIBUTES), NULL, NULL, 0, NULL, NULL };
          ISYSCALL(NtOpenProcess)(&hProcess, (ACCESS_MASK)(0x0010 | 0x0400 | 0x1000), &poa, &cid); }
        if (!hProcess) return false;

        PVOID remoteOgl = FindRemoteModule(hProcess, xorstr_(L"opengl32.dll"));
        if (!remoteOgl) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        // Read PE headers
        BYTE* hdrBuf = NULL;
        { SIZE_T allocSz = 2048;
          ISYSCALL(NtAllocateVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, (ULONG_PTR)0, &allocSz, (ULONG)0x3000, (ULONG)0x04); }
        if (!hdrBuf) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        SIZE_T read = 0;
        if (!NT_SUCCESS(ISYSCALL(NtReadVirtualMemory)(hProcess, remoteOgl, hdrBuf, (SIZE_T)2048, &read))) {
            { SIZE_T freeSz = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, &freeSz, (ULONG)0x8000); };
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        auto dos = (IMAGE_DOS_HEADER*)hdrBuf;
        if (dos->e_magic != 0x5A4D) {
            { SIZE_T freeSz = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, &freeSz, (ULONG)0x8000); };
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        auto ntHdr = (IMAGE_NT_HEADERS*)(hdrBuf + dos->e_lfanew);
        auto sec = IMAGE_FIRST_SECTION(ntHdr);
        WORD numSec = ntHdr->FileHeader.NumberOfSections;

        DWORD roTotalPages = 0;
        DWORD roPrivatePages = 0;

        for (WORD s = 0; s < numSec; s++) {
            DWORD chars = sec[s].Characteristics;
            bool isExec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isWrite = (chars & IMAGE_SCN_MEM_WRITE) != 0;
            bool isRead = (chars & IMAGE_SCN_MEM_READ) != 0;
            bool isReadOnly = isRead && !isWrite && !isExec;

            if (!isReadOnly || sec[s].Misc.VirtualSize == 0)
                continue;

            DWORD pageSize = 0x1000;
            DWORD numPages = (sec[s].Misc.VirtualSize + pageSize - 1) / pageSize;

            for (DWORD batch = 0; batch < numPages; batch += 64) {
                DWORD count = numPages - batch;
                if (count > 64) count = 64;

                MY_WSEX_INFO wsInfo[64];
                for (DWORD p = 0; p < count; p++) {
                    wsInfo[p].VirtualAddress =
                        (BYTE*)remoteOgl + sec[s].VirtualAddress + ((batch + p) * pageSize);
                    wsInfo[p].VirtualAttributes.Flags = 0;
                }

                NTSTATUS wsResult = ISYSCALL(NtQueryVirtualMemory)(
                    hProcess, (PVOID)NULL, (ULONG)4,
                    (PVOID)wsInfo, (SIZE_T)(count * sizeof(MY_WSEX_INFO)), (PSIZE_T)NULL);

                if (NT_SUCCESS(wsResult)) {
                    for (DWORD p = 0; p < count; p++) {
                        if (wsInfo[p].VirtualAttributes.Valid) {
                            roTotalPages++;
                            if (!wsInfo[p].VirtualAttributes.Shared)
                                roPrivatePages++;
                        }
                    }
                }
            }
        }

        ISYSCALL(NtClose)(hProcess);
        { SIZE_T freeSz = 0; ISYSCALL(NtFreeVirtualMemory)((HANDLE)-1, (PVOID*)&hdrBuf, &freeSz, (ULONG)0x8000); };

        if (roTotalPages == 0) return false;

        double ratio = (double)roPrivatePages / (double)roTotalPages;
        return (ratio >= 0.50);
    }

    // =============================================
    //  HD-Player opengl32.dll glDrawElements CoW detection

    __declspec(noinline) bool CheckGameTextHooks() {
        DWORD pid = FindProcessByName(xorstr_(L"HD-Player.exe"));
        if (!pid) return false;

        HANDLE hProcess = NULL;
        { MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
          MY_OBJECT_ATTRIBUTES poa = { sizeof(MY_OBJECT_ATTRIBUTES), NULL, NULL, 0, NULL, NULL };
          ISYSCALL(NtOpenProcess)(&hProcess, (ACCESS_MASK)(0x0010 | 0x0400), &poa, &cid); }
        if (!hProcess) return false;

        PVOID remoteOgl = FindRemoteModule(hProcess, xorstr_(L"opengl32.dll"));
        if (!remoteOgl) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        // opengl32.dll pre-loaded in main before anti-dump
        // (LoadLibraryA after PEB unlink would create a new MEM_IMAGE mapping)
        if (!::g_OpenGL32Base) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        BYTE* localBase = ::g_OpenGL32Base;
        auto dos = (IMAGE_DOS_HEADER*)localBase;
        auto nt = (IMAGE_NT_HEADERS*)(localBase + dos->e_lfanew);
        auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0) {
            ISYSCALL(NtClose)(hProcess);
            return false;
        }

        auto exp = (IMAGE_EXPORT_DIRECTORY*)(localBase + expDir.VirtualAddress);
        auto names = (DWORD*)(localBase + exp->AddressOfNames);
        auto funcs = (DWORD*)(localBase + exp->AddressOfFunctions);
        auto ords = (WORD*)(localBase + exp->AddressOfNameOrdinals);

        // djb2 hashes
        constexpr auto H = [](const char* s) constexpr -> DWORD {
            DWORD h = 5381;
            while (*s) { h = ((h << 5) + h) + (unsigned char)*s; s++; }
            return h;
        };

        struct Target {
            DWORD nameHash;
            DWORD rva;
        };

        Target targets[] = {
            { H("glDrawElements"),      0 },
            { H("glDrawArrays"),        0 },
            { H("wglSwapBuffers"),      0 },
        };
        constexpr int NUM_TARGETS = 3;

        int found = 0;
        for (DWORD i = 0; i < exp->NumberOfNames && found < NUM_TARGETS; i++) {
            const char* name = (const char*)(localBase + names[i]);

            DWORD h = 5381;
            const char* p = name;
            while (*p) { h = ((h << 5) + h) + (unsigned char)*p; p++; }

            for (int t = 0; t < NUM_TARGETS; t++) {
                if (targets[t].rva == 0 && targets[t].nameHash == h) {
                    targets[t].rva = funcs[ords[i]];
                    found++;
                    break;
                }
            }
        }

        // Query the specific pages where these functions live
        // If any page is private → CoW occurred → someone wrote there
        bool tampered = false;

        for (int t = 0; t < NUM_TARGETS; t++) {
            if (targets[t].rva == 0) continue;

            // Page-align the function RVA
            DWORD pageRva = targets[t].rva & ~0xFFF;
            PVOID remotePage = (BYTE*)remoteOgl + pageRva;

            MY_WSEX_INFO wsInfo;
            wsInfo.VirtualAddress = remotePage;
            wsInfo.VirtualAttributes.Flags = 0;

            if (NT_SUCCESS(ISYSCALL(NtQueryVirtualMemory)(
                hProcess, (PVOID)NULL, (ULONG)4,
                (PVOID)&wsInfo, (SIZE_T)sizeof(MY_WSEX_INFO), (PSIZE_T)NULL)))
            {
                if (wsInfo.VirtualAttributes.Valid &&
                    !wsInfo.VirtualAttributes.Shared) {
                    // Page is private = CoW = someone wrote to this page
                    tampered = true;
                    break;
                }
            }
        }

        ISYSCALL(NtClose)(hProcess);
        return tampered;
    }

} // namespace EventLogDetect
