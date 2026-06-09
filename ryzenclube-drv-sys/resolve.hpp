#pragma once
#include <ntifs.h>

extern "C" NTKERNELAPI PVOID NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

typedef NTSTATUS (NTAPI*    fn_MmCopyVirtualMemory)(PEPROCESS,PVOID,PEPROCESS,PVOID,SIZE_T,KPROCESSOR_MODE,PSIZE_T);
typedef NTSTATUS (NTAPI*    fn_PsLookupProcessByProcessId)(HANDLE,PEPROCESS*);
typedef NTSTATUS (NTAPI*    fn_ObOpenObjectByPointer)(PVOID,ULONG,PVOID,ACCESS_MASK,POBJECT_TYPE,KPROCESSOR_MODE,PHANDLE);
typedef PPEB     (NTAPI*    fn_PsGetProcessPeb)(PEPROCESS);
typedef BOOLEAN  (NTAPI*    fn_MmIsAddressValid)(PVOID);
typedef NTSTATUS (NTAPI*    fn_ZwQueryVirtualMemory)(HANDLE,PVOID,MEMORY_INFORMATION_CLASS,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI*    fn_ZwOpenSection)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI*    fn_ZwMapViewOfSection)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,SECTION_INHERIT,ULONG,ULONG);
typedef NTSTATUS (NTAPI*    fn_ZwUnmapViewOfSection)(HANDLE,PVOID);
typedef NTSTATUS (NTAPI*    fn_ZwClose)(HANDLE);
typedef NTSTATUS (NTAPI*    fn_RtlGetVersion)(PRTL_OSVERSIONINFOW);
typedef LONG_PTR (FASTCALL* fn_ObfDereferenceObject)(PVOID);
typedef PEPROCESS(NTAPI*    fn_IoGetCurrentProcess)();

static fn_MmCopyVirtualMemory        g_MmCopyVirtualMemory        = nullptr;
static fn_PsLookupProcessByProcessId g_PsLookupProcessByProcessId = nullptr;
static fn_ObOpenObjectByPointer      g_ObOpenObjectByPointer      = nullptr;
static fn_PsGetProcessPeb            g_PsGetProcessPeb            = nullptr;
static fn_MmIsAddressValid           g_MmIsAddressValid           = nullptr;
static fn_ZwQueryVirtualMemory       g_ZwQueryVirtualMemory       = nullptr;
static fn_ZwOpenSection              g_ZwOpenSection              = nullptr;
static fn_ZwMapViewOfSection         g_ZwMapViewOfSection         = nullptr;
static fn_ZwUnmapViewOfSection       g_ZwUnmapViewOfSection       = nullptr;
static fn_ZwClose                    g_ZwClose                    = nullptr;
static fn_RtlGetVersion              g_RtlGetVersion              = nullptr;
static fn_ObfDereferenceObject       g_ObfDereferenceObject       = nullptr;
static fn_IoGetCurrentProcess        g_IoGetCurrentProcess        = nullptr;
static POBJECT_TYPE*                 g_pPsProcessType             = nullptr;

static __forceinline PVOID KResolve(wchar_t* name, int len) {
    UNICODE_STRING us;
    us.Buffer        = name;
    us.Length        = (USHORT)(len * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    return MmGetSystemRoutineAddress(&us);
}

static int ResolveKernelApis() {
    int resolved = 0;

    { wchar_t n[] = {'M','m','C','o','p','y','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
      g_MmCopyVirtualMemory = (fn_MmCopyVirtualMemory)KResolve(n, 19); if (g_MmCopyVirtualMemory) resolved++; }

    { wchar_t n[] = {'P','s','L','o','o','k','u','p','P','r','o','c','e','s','s','B','y','P','r','o','c','e','s','s','I','d',0};
      g_PsLookupProcessByProcessId = (fn_PsLookupProcessByProcessId)KResolve(n, 26); if (g_PsLookupProcessByProcessId) resolved++; }

    { wchar_t n[] = {'O','b','O','p','e','n','O','b','j','e','c','t','B','y','P','o','i','n','t','e','r',0};
      g_ObOpenObjectByPointer = (fn_ObOpenObjectByPointer)KResolve(n, 21); if (g_ObOpenObjectByPointer) resolved++; }

    { wchar_t n[] = {'P','s','G','e','t','P','r','o','c','e','s','s','P','e','b',0};
      g_PsGetProcessPeb = (fn_PsGetProcessPeb)KResolve(n, 15); if (g_PsGetProcessPeb) resolved++; }

    { wchar_t n[] = {'M','m','I','s','A','d','d','r','e','s','s','V','a','l','i','d',0};
      g_MmIsAddressValid = (fn_MmIsAddressValid)KResolve(n, 16); if (g_MmIsAddressValid) resolved++; }

    { wchar_t n[] = {'Z','w','Q','u','e','r','y','V','i','r','t','u','a','l','M','e','m','o','r','y',0};
      g_ZwQueryVirtualMemory = (fn_ZwQueryVirtualMemory)KResolve(n, 20); if (g_ZwQueryVirtualMemory) resolved++; }

    { wchar_t n[] = {'Z','w','O','p','e','n','S','e','c','t','i','o','n',0};
      g_ZwOpenSection = (fn_ZwOpenSection)KResolve(n, 13); if (g_ZwOpenSection) resolved++; }

    { wchar_t n[] = {'Z','w','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0};
      g_ZwMapViewOfSection = (fn_ZwMapViewOfSection)KResolve(n, 18); if (g_ZwMapViewOfSection) resolved++; }

    { wchar_t n[] = {'Z','w','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0};
      g_ZwUnmapViewOfSection = (fn_ZwUnmapViewOfSection)KResolve(n, 20); if (g_ZwUnmapViewOfSection) resolved++; }

    { wchar_t n[] = {'Z','w','C','l','o','s','e',0};
      g_ZwClose = (fn_ZwClose)KResolve(n, 7); if (g_ZwClose) resolved++; }

    { wchar_t n[] = {'R','t','l','G','e','t','V','e','r','s','i','o','n',0};
      g_RtlGetVersion = (fn_RtlGetVersion)KResolve(n, 13); if (g_RtlGetVersion) resolved++; }

    { wchar_t n[] = {'O','b','f','D','e','r','e','f','e','r','e','n','c','e','O','b','j','e','c','t',0};
      g_ObfDereferenceObject = (fn_ObfDereferenceObject)KResolve(n, 20); if (g_ObfDereferenceObject) resolved++; }

    { wchar_t n[] = {'I','o','G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s',0};
      g_IoGetCurrentProcess = (fn_IoGetCurrentProcess)KResolve(n, 19); if (g_IoGetCurrentProcess) resolved++; }

    { wchar_t n[] = {'P','s','P','r','o','c','e','s','s','T','y','p','e',0};
      g_pPsProcessType = (POBJECT_TYPE*)KResolve(n, 13); if (g_pPsProcessType) resolved++; }

    return resolved;
}
