#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#include "shared.h"

#undef ObDereferenceObject
#undef PsGetCurrentProcess

#ifndef MEM_IMAGE
#define MEM_IMAGE   0x1000000
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED  0x40000
#endif
#ifndef MEM_PRIVATE
#define MEM_PRIVATE 0x20000
#endif

#include "resolve.hpp"
#include "remote.hpp"
#include "vad.hpp"
#include "cow.hpp"
#include "stubs.hpp"

static NTSTATUS ScanTarget(DEEP_TARGET* Target) {
    if (Target->Pid == 0 || Target->ModuleName[0] == 0)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS eprocess = NULL;
    NTSTATUS status = g_PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Target->Pid, &eprocess);
    if (!NT_SUCCESS(status)) return status;

    HANDLE hProcess = NULL;
    status = g_ObOpenObjectByPointer(eprocess, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *g_pPsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) {
        g_ObfDereferenceObject(eprocess);
        return status;
    }

    PVOID  moduleBase = NULL;
    SIZE_T moduleSize = 0;
    status = FindRemoteModuleBase(hProcess, eprocess, Target->ModuleName, &moduleBase, &moduleSize);
    if (!NT_SUCCESS(status) || !moduleBase) {
        Target->Flags |= DEEP_FLAG_MODULE_MISSING;
        g_ZwClose(hProcess);
        g_ObfDereferenceObject(eprocess);
        return STATUS_SUCCESS;
    }

    // Check 1: memory type (MEM_IMAGE vs remapped)
    {
        MEMORY_BASIC_INFORMATION mbi;
        RtlZeroMemory(&mbi, sizeof(mbi));
        SIZE_T retLen = 0;
        status = g_ZwQueryVirtualMemory(hProcess, moduleBase, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
        if (NT_SUCCESS(status)) {
            Target->MemType = (unsigned long)mbi.Type;
            if (mbi.Type != MEM_IMAGE) Target->Flags |= DEEP_FLAG_REMAPPED;
        }
    }

    // Check 2: section file path
    {
        UCHAR secNameBuf[sizeof(UNICODE_STRING) + 520 * sizeof(wchar_t)];
        RtlZeroMemory(secNameBuf, sizeof(secNameBuf));
        SIZE_T retLen = 0;
        status = g_ZwQueryVirtualMemory(hProcess, moduleBase, MemorySectionNameInfo,
            secNameBuf, sizeof(secNameBuf), &retLen);
        if (NT_SUCCESS(status)) {
            PUNICODE_STRING sn = (PUNICODE_STRING)secNameBuf;
            if (sn->Buffer && sn->Length > 0) {
                USHORT nameChars = sn->Length / sizeof(wchar_t);
                if (nameChars > 259) nameChars = 259;
                RtlCopyMemory(Target->SectionPath, sn->Buffer, nameChars * sizeof(wchar_t));
                Target->SectionPath[nameChars] = L'\0';
                USHORT modLen = WstrLen(Target->ModuleName);
                if (!WstrIEndsWith(sn->Buffer, nameChars, Target->ModuleName, modLen))
                    Target->Flags |= DEEP_FLAG_WRONG_PATH;
            }
        } else {
            Target->Flags |= DEEP_FLAG_NO_SECTION;
        }
    }

    // Check 3 & 4: CoW detection + PE header + VAD ControlArea
    CheckMemoryIntegrity(hProcess, eprocess, moduleBase, Target);

    // Check 5: syscall stub integrity + VAD flags (ntdll only)
    {
        const wchar_t* ntdllName = L"ntdll.dll";
        USHORT ntdllLen = 9;
        USHORT modLen   = WstrLen(Target->ModuleName);
        if (modLen == ntdllLen) {
            BOOLEAN isNtdll = TRUE;
            for (USHORT j = 0; j < ntdllLen; j++) {
                if (WcharLower(Target->ModuleName[j]) != ntdllName[j]) { isNtdll = FALSE; break; }
            }
            ULONG vadFlags2 = Target->DbgWsExLowShare;
            if (isNtdll) {
                CheckCriticalStubs(eprocess, moduleBase, Target);
                if ((vadFlags2 >> 27) & 1) Target->Flags |= DEEP_FLAG_SECTION_REMAP;
            } else {
                if (!((vadFlags2 >> 26) & 1)) Target->Flags |= DEEP_FLAG_SECTION_REMAP;
            }
        }
    }

    g_ZwClose(hProcess);
    g_ObfDereferenceObject(eprocess);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    int apiCount = ResolveKernelApis();
    if (apiCount != 14)
        return (NTSTATUS)(0xC0070000 | apiCount);

    RTL_OSVERSIONINFOW osVer;
    osVer.dwOSVersionInfoSize = sizeof(osVer);
    if (NT_SUCCESS(g_RtlGetVersion(&osVer)))
        g_OffVadRoot = (osVer.dwBuildNumber >= 26000) ? 0x558 : 0x7d8;

    wchar_t sectionNameBuf[80];
    DeriveSectionName(sectionNameBuf, 1);

    UNICODE_STRING sectionName;
    sectionName.Buffer        = sectionNameBuf;
    sectionName.Length        = WstrLen(sectionNameBuf) * sizeof(wchar_t);
    sectionName.MaximumLength = sectionName.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hSection = NULL;
    NTSTATUS status = g_ZwOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &oa);
    if (!NT_SUCCESS(status)) return status;

    PVOID  mappedBase = NULL;
    SIZE_T viewSize   = 0;
    status = g_ZwMapViewOfSection(hSection, ZwCurrentProcess(), &mappedBase,
        0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        g_ZwClose(hSection);
        return status;
    }

    DEEP_SCAN_REQUEST* request = (DEEP_SCAN_REQUEST*)mappedBase;
    CryptSharedMemory(request);

    if (request->Magic != DEEP_MAGIC_RT() || request->Command != DEEP_CMD_SCAN_RT()) {
        request->Status = DEEP_STATUS_ERROR_RT();
        CryptSharedMemory(request);
        g_ZwUnmapViewOfSection(ZwCurrentProcess(), mappedBase);
        g_ZwClose(hSection);
        return STATUS_INVALID_PARAMETER;
    }

    for (unsigned long i = 0; i < request->TargetCount && i < DEEP_MAX_TARGETS; i++)
        ScanTarget(&request->Targets[i]);

    request->Status = DEEP_STATUS_OK_RT();
    CryptSharedMemory(request);

    g_ZwUnmapViewOfSection(ZwCurrentProcess(), mappedBase);
    g_ZwClose(hSection);
    return STATUS_SUCCESS;
}
