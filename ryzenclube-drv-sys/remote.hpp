#pragma once

// PEB / LDR structures for remote process traversal

#pragma pack(push, 8)
typedef struct _REMOTE_PEB_LDR_DATA {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
} REMOTE_PEB_LDR_DATA;

typedef struct _REMOTE_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} REMOTE_LDR_ENTRY;

typedef struct _REMOTE_PEB_PARTIAL {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
} REMOTE_PEB_PARTIAL;
#pragma pack(pop)

// Wide string helpers (no CRT)

static USHORT WstrLen(const wchar_t* s) {
    USHORT len = 0;
    while (s[len]) len++;
    return len;
}

static wchar_t WcharLower(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? (c + 32) : c;
}

static BOOLEAN WstrIEndsWith(const wchar_t* hay, USHORT hayLen, const wchar_t* needle, USHORT needleLen) {
    if (needleLen > hayLen) return FALSE;
    const wchar_t* suffix = hay + (hayLen - needleLen);
    for (USHORT i = 0; i < needleLen; i++) {
        if (WcharLower(suffix[i]) != WcharLower(needle[i]))
            return FALSE;
    }
    return TRUE;
}

// MmCopyVirtualMemory wrapper

static NTSTATUS SafeReadRemote(PEPROCESS Process, PVOID RemoteAddr, PVOID LocalBuf, SIZE_T Size) {
    SIZE_T bytesRead = 0;
    return g_MmCopyVirtualMemory(Process, RemoteAddr, g_IoGetCurrentProcess(), LocalBuf, Size, KernelMode, &bytesRead);
}

// Walk remote PEB LDR to find a module by name

static NTSTATUS FindRemoteModuleBase(
    HANDLE        hProcess,
    PEPROCESS     Process,
    const wchar_t* ModuleName,
    PVOID*        OutBase,
    SIZE_T*       OutSize
) {
    UNREFERENCED_PARAMETER(hProcess);
    *OutBase = NULL;
    *OutSize = 0;

    PPEB pebAddr = g_PsGetProcessPeb(Process);
    if (!pebAddr) return STATUS_NOT_FOUND;

    REMOTE_PEB_PARTIAL peb;
    RtlZeroMemory(&peb, sizeof(peb));
    NTSTATUS status = SafeReadRemote(Process, pebAddr, &peb, sizeof(peb));
    if (!NT_SUCCESS(status) || !peb.Ldr) return STATUS_NOT_FOUND;

    REMOTE_PEB_LDR_DATA ldr;
    RtlZeroMemory(&ldr, sizeof(ldr));
    status = SafeReadRemote(Process, peb.Ldr, &ldr, sizeof(ldr));
    if (!NT_SUCCESS(status) || !ldr.Initialized) return STATUS_NOT_FOUND;

    PVOID listHead    = (PVOID)((ULONG_PTR)peb.Ldr + FIELD_OFFSET(REMOTE_PEB_LDR_DATA, InLoadOrderModuleList));
    PVOID current     = ldr.InLoadOrderModuleList.Flink;
    USHORT needleLen  = WstrLen(ModuleName);

    for (int i = 0; i < 200 && current != listHead; i++) {
        REMOTE_LDR_ENTRY entry;
        RtlZeroMemory(&entry, sizeof(entry));
        status = SafeReadRemote(Process, current, &entry, sizeof(entry));
        if (!NT_SUCCESS(status)) break;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            USHORT nameChars = entry.BaseDllName.Length / sizeof(wchar_t);
            if (nameChars == needleLen && nameChars < 128) {
                wchar_t nameBuf[128];
                RtlZeroMemory(nameBuf, sizeof(nameBuf));
                status = SafeReadRemote(Process, entry.BaseDllName.Buffer, nameBuf, nameChars * sizeof(wchar_t));
                if (NT_SUCCESS(status)) {
                    BOOLEAN match = TRUE;
                    for (USHORT j = 0; j < nameChars; j++) {
                        if (WcharLower(nameBuf[j]) != WcharLower(ModuleName[j])) { match = FALSE; break; }
                    }
                    if (match) {
                        *OutBase = entry.DllBase;
                        *OutSize = entry.SizeOfImage;
                        return STATUS_SUCCESS;
                    }
                }
            }
        }
        current = entry.InLoadOrderLinks.Flink;
    }
    return STATUS_NOT_FOUND;
}
