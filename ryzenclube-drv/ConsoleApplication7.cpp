#include <windows.h>
#include <wintrust.h>

#include "XorStr.hpp"
#include "Lazyimporter.hpp"
#include "IndirectSyscall.hpp"
#include "VmDetect.hpp"

// =============================================
//  Intrinsics — required by /NODEFAULTLIB
// =============================================

#ifdef _MSC_VER
#pragma function(memset)
#pragma function(memcpy)
#endif
extern "C" void* memset(void* dest, int c, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--) *p++ = (unsigned char)c;
    return dest;
}

extern "C" void* memcpy(void* dest, const void* src, size_t count) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) *d++ = *s++;
    return dest;
}

// MSVC security cookie stub
extern "C" {
    int _fltused = 0;
    uintptr_t __security_cookie = 0xBB40E64E;

    void __cdecl __security_check_cookie(uintptr_t) {}
}

// =============================================
//  NT Type Definitions
// =============================================

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define OBJ_CASE_INSENSITIVE 0x00000040L

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    MY_UNICODE_STRING* ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

typedef struct _MY_IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} MY_IO_STATUS_BLOCK;

typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID;

typedef struct _KV_BASIC_INFO {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KV_BASIC_INFO;

typedef struct _KV_PARTIAL_INFO {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KV_PARTIAL_INFO;

typedef struct _F_BASIC_INFO {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} F_BASIC_INFO;

typedef struct _F_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} F_STANDARD_INFO;

typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
    BYTE              Reserved1[16];
    PVOID             Reserved2[10];
    MY_UNICODE_STRING ImagePathName;
    MY_UNICODE_STRING CommandLine;
} MY_RTL_USER_PROCESS_PARAMETERS;

typedef struct _MY_PEB {
    BYTE                            Reserved1[2];
    BYTE                            BeingDebugged;
    BYTE                            Reserved2[1];
    PVOID                           Reserved3[2];
    PVOID                           Ldr;
    MY_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
} MY_PEB;

// WINTRUST GUID — WINTRUST_ACTION_GENERIC_VERIFY_V2
static const GUID g_WVTGuid =
{ 0xaac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };

// =============================================
//  NT Function Declarations (for lazy import decltype)
// =============================================

extern "C" {
    NTSTATUS NTAPI NtOpenKey(
        PHANDLE, ACCESS_MASK, MY_OBJECT_ATTRIBUTES*);
    NTSTATUS NTAPI NtClose(HANDLE);
    NTSTATUS NTAPI NtEnumerateValueKey(
        HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
    NTSTATUS NTAPI NtQueryValueKey(
        HANDLE, MY_UNICODE_STRING*, ULONG, PVOID, ULONG, PULONG);
    NTSTATUS NTAPI NtOpenFile(
        PHANDLE, ACCESS_MASK, MY_OBJECT_ATTRIBUTES*,
        MY_IO_STATUS_BLOCK*, ULONG, ULONG);
    NTSTATUS NTAPI NtQueryInformationFile(
        HANDLE, MY_IO_STATUS_BLOCK*, PVOID, ULONG, ULONG);
    NTSTATUS NTAPI NtQueryAttributesFile(
        MY_OBJECT_ATTRIBUTES*, PVOID);
    NTSTATUS NTAPI NtSetInformationFile(
        HANDLE, MY_IO_STATUS_BLOCK*, PVOID, ULONG, ULONG);
    NTSTATUS NTAPI NtQueryVirtualMemory(
        HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS NTAPI NtQueryInformationProcess(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
    VOID NTAPI RtlInitUnicodeString(MY_UNICODE_STRING*, PCWSTR);
    LONG NTAPI RtlCompareUnicodeString(
        MY_UNICODE_STRING*, MY_UNICODE_STRING*, BOOLEAN);
    NTSTATUS NTAPI RtlAdjustPrivilege(
        ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
    NTSTATUS NTAPI NtUnmapViewOfSection(
        HANDLE ProcessHandle, PVOID BaseAddress);
    NTSTATUS NTAPI NtAllocateVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    NTSTATUS NTAPI NtProtectVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect);
    NTSTATUS NTAPI NtFreeVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    NTSTATUS NTAPI NtCreateSection(
        PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
        MY_OBJECT_ATTRIBUTES* ObjectAttributes, PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
    NTSTATUS NTAPI NtMapViewOfSection(
        HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
        ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
        ULONG Win32Protect);
    NTSTATUS NTAPI NtGetContextThread(
        HANDLE ThreadHandle, PCONTEXT ThreadContext);
    NTSTATUS NTAPI NtWriteFile(
        HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
        MY_IO_STATUS_BLOCK* IoStatusBlock, PVOID Buffer, ULONG Length,
        PLARGE_INTEGER ByteOffset, PULONG Key);
    NTSTATUS NTAPI NtReadFile(
        HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
        MY_IO_STATUS_BLOCK* IoStatusBlock, PVOID Buffer, ULONG Length,
        PLARGE_INTEGER ByteOffset, PULONG Key);
    NTSTATUS NTAPI NtTerminateProcess(
        HANDLE ProcessHandle, NTSTATUS ExitStatus);
    NTSTATUS NTAPI NtOpenProcess(
        PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        MY_OBJECT_ATTRIBUTES* ObjectAttributes, MY_CLIENT_ID* ClientId);
    NTSTATUS NTAPI NtReadVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    NTSTATUS NTAPI NtQuerySystemInformation(
        ULONG SystemInformationClass, PVOID SystemInformation,
        ULONG SystemInformationLength, PULONG ReturnLength);
    NTSTATUS NTAPI NtCreateKey(
        PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
        MY_OBJECT_ATTRIBUTES* ObjectAttributes, ULONG TitleIndex,
        MY_UNICODE_STRING* Class, ULONG CreateOptions, PULONG Disposition);
    NTSTATUS NTAPI NtSetValueKey(
        HANDLE KeyHandle, MY_UNICODE_STRING* ValueName,
        ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
    NTSTATUS NTAPI NtDeleteKey(HANDLE KeyHandle);
    NTSTATUS NTAPI NtLoadDriver(MY_UNICODE_STRING* DriverServiceName);
    NTSTATUS NTAPI NtUnloadDriver(MY_UNICODE_STRING* DriverServiceName);
    NTSTATUS NTAPI NtDeviceIoControlFile(
        HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
        MY_IO_STATUS_BLOCK* IoStatusBlock, ULONG IoControlCode,
        PVOID InputBuffer, ULONG InputBufferLength,
        PVOID OutputBuffer, ULONG OutputBufferLength);
}

#include "AntiMon.hpp"
#include "AntiHook.hpp"
#include "AntiDebug.hpp"
#include "AntiDump.hpp"

// Deep scan shared structures (scanner <-> kernel driver)
#include "../DeepScan/shared.h"

// =============================================
//  Inline string ops — zero CRT
// =============================================

__forceinline size_t slen(const char* s) {
    const char* p = s; while (*p) p++; return p - s;
}

size_t wlen(const wchar_t* s) {
    const wchar_t* p = s; while (*p) p++; return p - s;
}

void wcpy(wchar_t* d, const wchar_t* s, size_t max) {
    size_t i = 0;
    while (s[i] && i < max - 1) { d[i] = s[i]; i++; }
    d[i] = 0;
}

__forceinline wchar_t wlo(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? c + 32 : c;
}

__forceinline void wlower(wchar_t* s) {
    while (*s) { *s = wlo(*s); s++; }
}

int wicmp(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = wlo(*a), cb = wlo(*b);
        if (ca != cb) return (int)(ca - cb);
        a++; b++;
    }
    return (int)(*a - *b);
}

__forceinline bool wcontains(const wchar_t* hay, const wchar_t* needle) {
    if (!*needle) return true;
    for (; *hay; hay++) {
        const wchar_t* h = hay;
        const wchar_t* n = needle;
        while (*h && *n && wlo(*h) == wlo(*n)) { h++; n++; }
        if (!*n) return true;
    }
    return false;
}

// =============================================
//  Console IO — NtWriteFile/NtReadFile, zero kernel32
// =============================================

static HANDLE g_hOut = NULL;
static HANDLE g_hIn  = NULL;

// Read StandardOutput/StandardInput directly from PEB
// PEB+0x20 = ProcessParameters
// ProcessParameters+0x20 = StandardInput
// ProcessParameters+0x28 = StandardOutput
__forceinline HANDLE GetStdOutFromPEB() {
#if defined(_M_X64) || defined(__amd64__)
    auto peb = (BYTE*)__readgsqword(0x60);
#else
    auto peb = (BYTE*)__readfsdword(0x30);
#endif
    auto params = *(BYTE**)(peb + 0x20);
    return *(HANDLE*)(params + 0x28);
}

__forceinline HANDLE GetStdInFromPEB() {
#if defined(_M_X64) || defined(__amd64__)
    auto peb = (BYTE*)__readgsqword(0x60);
#else
    auto peb = (BYTE*)__readfsdword(0x30);
#endif
    auto params = *(BYTE**)(peb + 0x20);
    return *(HANDLE*)(params + 0x20);
}

__forceinline void ConWrite(const char* s) {
    MY_IO_STATUS_BLOCK iosb = { 0 };
    ISYSCALL(NtWriteFile)(
        g_hOut, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
        &iosb, (PVOID)s, (ULONG)slen(s),
        (PLARGE_INTEGER)NULL, (PULONG)NULL);
}

__forceinline void ConWriteN(const char* s, DWORD len) {
    MY_IO_STATUS_BLOCK iosb = { 0 };
    ISYSCALL(NtWriteFile)(
        g_hOut, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
        &iosb, (PVOID)s, len,
        (PLARGE_INTEGER)NULL, (PULONG)NULL);
}

// Int to decimal string (max 10 digits)
__forceinline void ConWriteInt(int val) {
    char buf[12];
    int i = 0;
    if (val == 0) { ConWrite("0"); return; }
    if (val < 0) { ConWrite("-"); val = -val; }
    while (val > 0 && i < 10) { buf[i++] = '0' + (val % 10); val /= 10; }
    // reverse
    for (int j = i - 1; j >= 0; j--)
        ConWriteN(&buf[j], 1);
}

__forceinline void ConWriteHex(unsigned long val) {
    const char* hex = "0123456789ABCDEF";
    char buf[9];
    int i = 0;
    if (val == 0) { ConWrite("0"); return; }
    while (val > 0 && i < 8) { buf[i++] = hex[val & 0xF]; val >>= 4; }
    for (int j = i - 1; j >= 0; j--)
        ConWriteN(&buf[j], 1);
}

__forceinline void ConReadKey() {
    MY_IO_STATUS_BLOCK iosb = { 0 };
    char buf[16];
    ISYSCALL(NtReadFile)(
        g_hIn, (HANDLE)NULL, (PVOID)NULL, (PVOID)NULL,
        &iosb, buf, (ULONG)sizeof(buf),
        (PLARGE_INTEGER)NULL, (PULONG)NULL);
}

// =============================================
//  Console color — ANSI VT100 escape sequences
//  Written via NtWriteFile, zero kernel32
// =============================================

#define CLR_RED     12
#define CLR_GREEN   10
#define CLR_YELLOW  14
#define CLR_WHITE   15

__forceinline void SetColor(WORD c) {
    const char* esc;
    switch (c) {
        case CLR_RED:    esc = "\x1b[91m"; break;
        case CLR_GREEN:  esc = "\x1b[92m"; break;
        case CLR_YELLOW: esc = "\x1b[93m"; break;
        default:         esc = "\x1b[97m"; break; // white
    }
    ConWrite(esc);
}

void PrintFlag(const char* label, bool hit) {
    ConWrite("  [");
    SetColor(hit ? CLR_RED : CLR_GREEN);
    ConWrite(hit ? xorstr_(" FLAGGED ") : xorstr_("NO DETECT"));
    SetColor(CLR_WHITE);
    ConWrite("]  ");
    ConWrite(label);
    ConWrite("\n");
}

void PrintWarn(const char* label, bool hit) {
    ConWrite("  [");
    SetColor(hit ? CLR_YELLOW : CLR_GREEN);
    ConWrite(hit ? xorstr_(" WARNING ") : xorstr_("NO DETECT"));
    SetColor(CLR_WHITE);
    ConWrite("]  ");
    ConWrite(label);
    ConWrite("\n");
}

void PrintIntegrity(const char* label, bool modified) {
    ConWrite("  [");
    SetColor(modified ? CLR_RED : CLR_GREEN);
    ConWrite(modified ? xorstr_("TAMPERED") : xorstr_(" INTACT "));
    SetColor(CLR_WHITE);
    ConWrite("]  ");
    ConWrite(label);
    ConWrite("\n");
}

// =============================================
//  Pre-saved module bases — set before PEB unlink
//  After UnlinkAllFromPEB, PEB LDR lists are empty
//  so direct PEB reads and LoadLibraryA no longer work
// =============================================

BYTE* g_LocalNtdllBase = nullptr;
BYTE* g_OpenGL32Base = nullptr;
wchar_t g_ExeDirectory[MAX_PATH] = {};

// Embedded driver byte arrays
#include "VulnDriver.h"
#include "DeepScanDriver.h"

#include "DriverMapper.hpp"
#include "EventLogDetect.hpp"

// =============================================
//  UNICODE_STRING + OBJECT_ATTRIBUTES helpers
// =============================================

__forceinline void InitUStr(MY_UNICODE_STRING* us, wchar_t* buf, size_t bufChars, const wchar_t* src) {
    wcpy(buf, src, bufChars);
    size_t len = wlen(buf);
    us->Buffer = buf;
    us->Length = (USHORT)(len * sizeof(wchar_t));
    us->MaximumLength = (USHORT)(bufChars * sizeof(wchar_t));
}

__forceinline void InitObjAttr(MY_OBJECT_ATTRIBUTES* oa, MY_UNICODE_STRING* name) {
    oa->Length = sizeof(MY_OBJECT_ATTRIBUTES);
    oa->RootDirectory = NULL;
    oa->ObjectName = name;
    oa->Attributes = OBJ_CASE_INSENSITIVE;
    oa->SecurityDescriptor = NULL;
    oa->SecurityQualityOfService = NULL;
}

// =============================================
//  Registry helpers — all lazy imported
// =============================================

__declspec(noinline) HANDLE NtOpenRegKey(const wchar_t* xorPath) {
    wchar_t pathBuf[512];
    MY_UNICODE_STRING keyPath;
    MY_OBJECT_ATTRIBUTES oa;
    wcpy(pathBuf, xorPath, 512);
    InitUStr(&keyPath, pathBuf, 512, pathBuf);
    InitObjAttr(&oa, &keyPath);
    HANDLE hKey = NULL;
    NTSTATUS st = ISYSCALL(NtOpenKey)(&hKey, KEY_READ, &oa);
    return NT_SUCCESS(st) ? hKey : NULL;
}

__declspec(noinline) bool NtReadRegDword(HANDLE hKey, const wchar_t* xorName, DWORD* out) {
    wchar_t nameBuf[128];
    MY_UNICODE_STRING valueName;
    wcpy(nameBuf, xorName, 128);
    InitUStr(&valueName, nameBuf, 128, nameBuf);
    BYTE buf[256];
    ULONG len = 0;
    NTSTATUS st = ISYSCALL(NtQueryValueKey)(hKey, &valueName, 2, buf, sizeof(buf), &len);
    if (!NT_SUCCESS(st)) return false;
    KV_PARTIAL_INFO* info = (KV_PARTIAL_INFO*)buf;
    if (info->Type != REG_DWORD || info->DataLength != sizeof(DWORD)) return false;
    *out = *(DWORD*)info->Data;
    return true;
}

__declspec(noinline) bool NtReadRegString(HANDLE hKey, const wchar_t* xorName, wchar_t* out, ULONG maxChars) {
    wchar_t nameBuf[128];
    MY_UNICODE_STRING valueName;
    wcpy(nameBuf, xorName, 128);
    InitUStr(&valueName, nameBuf, 128, nameBuf);
    BYTE buf[1024];
    ULONG len = 0;
    NTSTATUS st = ISYSCALL(NtQueryValueKey)(hKey, &valueName, 2, buf, sizeof(buf), &len);
    if (!NT_SUCCESS(st)) return false;
    KV_PARTIAL_INFO* info = (KV_PARTIAL_INFO*)buf;
    if (info->Type != REG_SZ && info->Type != REG_EXPAND_SZ) return false;
    ULONG chars = info->DataLength / sizeof(wchar_t);
    if (chars >= maxChars) chars = maxChars - 1;
    for (ULONG i = 0; i < chars; i++) out[i] = ((wchar_t*)info->Data)[i];
    out[chars] = L'\0';
    return true;
}

// =============================================
//  Registry noise — open decoy keys to pollute
//  kernel CmRegisterCallbackEx logs.
//  If the attacker only filters our real keys,
//  they can't tell which ones matter.
// =============================================

__declspec(noinline) void RegNoise() {
    // Open + close common Windows registry keys to pollute
    // kernel CmRegisterCallbackEx logs. Each call is inline
    // to avoid static arrays (which need CRT thread-safe init).
    HANDLE h;

    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Lsa"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Ole"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Power"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0"));
    if (h) ISYSCALL(NtClose)(h);
    h = NtOpenRegKey(xorstr_(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions"));
    if (h) ISYSCALL(NtClose)(h);
}

// =============================================
//  Flag 1 — Defender exclusion
// =============================================

bool CheckDefenderExclusion() {
    HANDLE hKey = NtOpenRegKey(xorstr_(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"));
    if (!hKey)
        hKey = NtOpenRegKey(xorstr_(
            L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"));
    if (!hKey) return false;

    wchar_t t0[8], t1[8], t2[8];
    wcpy(t0, xorstr_(L"C:\\"),   8);
    wcpy(t1, xorstr_(L"C:"),     8);
    wcpy(t2, xorstr_(L"C:\\\\"), 8);

    MY_UNICODE_STRING targets[3];
    InitUStr(&targets[0], t0, 8, t0);
    InitUStr(&targets[1], t1, 8, t1);
    InitUStr(&targets[2], t2, 8, t2);

    BYTE buf[512];
    ULONG resultLen = 0;
    ULONG idx = 0;

    while (NT_SUCCESS(ISYSCALL(NtEnumerateValueKey)(hKey, idx, 0, buf, sizeof(buf), &resultLen))) {
        KV_BASIC_INFO* info = (KV_BASIC_INFO*)buf;
        MY_UNICODE_STRING valueName;
        valueName.Buffer        = info->Name;
        valueName.Length        = (USHORT)info->NameLength;
        valueName.MaximumLength = (USHORT)info->NameLength;

        for (int t = 0; t < 3; t++) {
            if (lzimpLI_FN(RtlCompareUnicodeString)(&valueName, &targets[t], TRUE) == 0) {
                ISYSCALL(NtClose)(hKey);
                return true;
            }
        }
        idx++;
    }
    ISYSCALL(NtClose)(hKey);
    return false;
}

// =============================================
//  Flag 2 — UAC EnableLUA
// =============================================

bool CheckUACDisabled() {
    HANDLE hKey = NtOpenRegKey(xorstr_(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"));
    if (!hKey) return false;
    DWORD enableLUA = 1;
    bool ok = NtReadRegDword(hKey, xorstr_(L"EnableLUA"), &enableLUA);
    ISYSCALL(NtClose)(hKey);
    return (ok && enableLUA == 0);
}

// =============================================
//  Flag 3 — SIP Hijack
// =============================================

bool CheckSIPHijack() {
    HANDLE hKey = NtOpenRegKey(xorstr_(
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0"
        L"\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"));

    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) {
            hKey = NtOpenRegKey(xorstr_(
                L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0"
                L"\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"));
        }
        if (!hKey) continue;

        wchar_t dllPath[MAX_PATH] = { 0 };
        wchar_t funcName[256]     = { 0 };
        NtReadRegString(hKey, xorstr_(L"Dll"),      dllPath,  MAX_PATH);
        NtReadRegString(hKey, xorstr_(L"FuncName"), funcName, 256);
        ISYSCALL(NtClose)(hKey);
        hKey = NULL;

        if (dllPath[0]) wlower(dllPath);

        if (wicmp(funcName, xorstr_(L"DbgUiContinue")) == 0)
            return true;
        if (wcontains(dllPath, xorstr_(L"ntdll.dll")))
            return true;
        if (dllPath[0] &&
            !wcontains(dllPath, xorstr_(L"wintrust.dll")) &&
            !wcontains(dllPath, xorstr_(L"windowscodecs.dll")) &&
            !wcontains(dllPath, xorstr_(L"msisip.dll")))
            return true;
    }
    return false;
}

// =============================================
//  Flag 4 — DWriteCore.dll in System32
// =============================================

bool CheckDroppedDll() {
    wchar_t pathBuf[256];
    MY_UNICODE_STRING filePath;
    MY_OBJECT_ATTRIBUTES oa;

    wcpy(pathBuf, xorstr_(L"\\??\\C:\\Windows\\System32\\DWriteCore.dll"), 256);
    InitUStr(&filePath, pathBuf, 256, pathBuf);
    InitObjAttr(&oa, &filePath);

    F_BASIC_INFO attrInfo = { 0 };
    NTSTATUS st = ISYSCALL(NtQueryAttributesFile)(&oa, &attrInfo);
    if (!NT_SUCCESS(st)) return false;

    HANDLE hFile = NULL;
    MY_IO_STATUS_BLOCK iosb = { 0 };
    st = ISYSCALL(NtOpenFile)(
        &hFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        0x00000020 | 0x00000004);

    if (!NT_SUCCESS(st)) return true;

    F_BASIC_INFO basicInfo = { 0 };
    ISYSCALL(NtQueryInformationFile)(hFile, &iosb, &basicInfo, sizeof(basicInfo), 4);
    F_STANDARD_INFO stdInfo = { 0 };
    ISYSCALL(NtQueryInformationFile)(hFile, &iosb, &stdInfo, sizeof(stdInfo), 5);
    ISYSCALL(NtClose)(hFile);

    return true;
}

// =============================================
//  Flag 5 — Self-signature canary
// =============================================

bool CheckSelfSignature() {
#if defined(_M_X64) || defined(__amd64__)
    MY_PEB* pPeb = (MY_PEB*)__readgsqword(0x60);
#else
    MY_PEB* pPeb = (MY_PEB*)__readfsdword(0x30);
#endif

    MY_UNICODE_STRING* pImagePath = &pPeb->ProcessParameters->ImagePathName;
    wchar_t exePath[MAX_PATH] = { 0 };
    USHORT copyLen = pImagePath->Length / sizeof(wchar_t);
    if (copyLen >= MAX_PATH) copyLen = MAX_PATH - 1;
    for (USHORT i = 0; i < copyLen; i++) exePath[i] = pImagePath->Buffer[i];
    exePath[copyLen] = L'\0';

    wchar_t* path = exePath;
    if (path[0] == L'\\' && path[1] == L'?' && path[2] == L'?' && path[3] == L'\\')
        path += 4;

    // wintrust.dll already pre-loaded before AntiDump::Init()
    GUID actionGuid = g_WVTGuid;

    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path;

    WINTRUST_DATA trustData;
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct            = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = lzimpLI_FN(WinVerifyTrust)(
        (HWND)INVALID_HANDLE_VALUE, &actionGuid, (LPVOID)&trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    lzimpLI_FN(WinVerifyTrust)(
        (HWND)INVALID_HANDLE_VALUE, &actionGuid, (LPVOID)&trustData);

    return (result == 0);
}

// =============================================
//  Warm up all lazy imports — cache function pointers
//  while PEB InLoadOrderModuleList is still intact.
//  After UnlinkAllFromPEB, the cached pointers still work
//  because DLL code remains in memory (phantom remap
//  preserves code, just changes VAD type to MEM_PRIVATE).
// =============================================

__declspec(noinline) void WarmUpLazyImports() {
    // kernel32.dll — only functions still used via lazy import
    // (everything else migrated to ISYSCALL)
    (void)lzimpLI_FN(VirtualProtect).cached();
    (void)lzimpLI_FN(LoadLibraryA).cached();
    (void)lzimpLI_FN(QueryPerformanceCounter).cached();
    (void)lzimpLI_FN(QueryPerformanceFrequency).cached();
    (void)lzimpLI_FN(EnumSystemFirmwareTables).cached();
    (void)lzimpLI_FN(GetSystemFirmwareTable).cached();
    (void)lzimpLI_FN(GetWindowThreadProcessId).cached();
    (void)lzimpLI_FN(FindWindowA).cached();

    // ntdll.dll — Rtl functions (not syscalls, must stay as lazy import)
    (void)lzimpLI_FN(RtlAdjustPrivilege).cached();
    (void)lzimpLI_FN(RtlCompareUnicodeString).cached();

    // advapi32.dll (pre-loaded)
    (void)lzimpLI_FN(OpenSCManagerW).cached();
    (void)lzimpLI_FN(OpenServiceW).cached();
    (void)lzimpLI_FN(CloseServiceHandle).cached();
    (void)lzimpLI_FN(QueryServiceStatusEx).cached();

    // wintrust.dll (pre-loaded)
    (void)lzimpLI_FN(WinVerifyTrust).cached();

    // kernel32.dll — deep scan (shared memory + driver mapper)
    (void)lzimpLI_FN(CreateFileMappingW).cached();
    (void)lzimpLI_FN(MapViewOfFile).cached();
    (void)lzimpLI_FN(UnmapViewOfFile).cached();
    (void)lzimpLI_FN(CloseHandle).cached();
    (void)lzimpLI_FN(CreateFileW).cached();
    (void)lzimpLI_FN(DeleteFileW).cached();
}

// =============================================
//  Deep Scan — kernel driver via integrated mapper
//
//  Creates shared memory, fills scan targets,
//  maps DeepScan.sys into kernel via iqvw64e.sys
//  using DriverMapper (ISYSCALL + lazy imports),
//  reads results from shared memory.
// =============================================

__declspec(noinline) void RunDeepScan() {
    // 1. Create named shared memory section (dynamic name)
    wchar_t sectionNameBuf[80];
    DeriveSectionName(sectionNameBuf, 0);

    HANDLE hMapping = lzimpLI_FN(CreateFileMappingW)(
        (HANDLE)-1, (LPSECURITY_ATTRIBUTES)NULL, (DWORD)PAGE_READWRITE,
        (DWORD)0, (DWORD)DEEP_SHARED_SIZE,
        sectionNameBuf);
    if (!hMapping) {
        SetColor(CLR_RED);
        ConWrite(xorstr_("  [!] Failed to create shared memory\n"));
        SetColor(CLR_WHITE);
        return;
    }

    DEEP_SCAN_REQUEST* request = (DEEP_SCAN_REQUEST*)lzimpLI_FN(MapViewOfFile)(
        hMapping, (DWORD)FILE_MAP_ALL_ACCESS, (DWORD)0, (DWORD)0, (SIZE_T)DEEP_SHARED_SIZE);
    if (!request) {
        lzimpLI_FN(CloseHandle)(hMapping);
        SetColor(CLR_RED);
        ConWrite(xorstr_("  [!] Failed to map shared memory\n"));
        SetColor(CLR_WHITE);
        return;
    }

    // Zero and fill request (obfuscated constants)
    memset(request, 0, sizeof(DEEP_SCAN_REQUEST));
    request->Magic   = DEEP_MAGIC_RT();
    request->Command = DEEP_CMD_SCAN_RT();
    request->Status  = DEEP_STATUS_PENDING_RT();

    // Target 1: EventLog service ntdll.dll
    DWORD evtPid = EventLogDetect::GetEventLogPID();
    if (evtPid) {
        request->Targets[request->TargetCount].Pid = evtPid;
        wcpy(request->Targets[request->TargetCount].ModuleName,
             xorstr_(L"ntdll.dll"), 64);
        request->TargetCount++;
    }

    // Target 2: HD-Player opengl32.dll
    DWORD hdPid = EventLogDetect::FindProcessByName(xorstr_(L"HD-Player.exe"));
    if (hdPid) {
        request->Targets[request->TargetCount].Pid = hdPid;
        wcpy(request->Targets[request->TargetCount].ModuleName,
             xorstr_(L"opengl32.dll"), 64);
        request->TargetCount++;
    }

    // Target 3: Sysmon.exe ntdll.dll (PPL — only accessible from kernel)
    DWORD sysmonPid = EventLogDetect::FindProcessByName(xorstr_(L"Sysmon.exe"));
    if (sysmonPid) {
        request->Targets[request->TargetCount].Pid = sysmonPid;
        wcpy(request->Targets[request->TargetCount].ModuleName,
             xorstr_(L"ntdll.dll"), 64);
        request->TargetCount++;
    }

    if (request->TargetCount == 0) {
        SetColor(CLR_YELLOW);
        ConWrite(xorstr_("  [!] No target processes found (EventLog / HD-Player / Sysmon)\n"));
        SetColor(CLR_WHITE);
        lzimpLI_FN(UnmapViewOfFile)((LPCVOID)request);
        lzimpLI_FN(CloseHandle)(hMapping);
        return;
    }

    // 2. Encrypt shared memory before driver access
    CryptSharedMemory(request);

    // 3. Map driver from embedded resources
    ConWrite(xorstr_("[*] Mapping kernel driver (indirect syscall)...\n"));

    NTSTATUS drvStatus = 0;
    bool mapped = DriverMapper::LoadAndMap(
        (BYTE*)g_VulnDriver, g_VulnDriverSize,
        (BYTE*)g_DeepScanDriver, g_DeepScanDriverSize,
        &drvStatus);

    if (!mapped) {
        SetColor(CLR_RED);
        ConWrite(xorstr_("  [!] Failed to map kernel driver\n"));
        SetColor(CLR_WHITE);
        lzimpLI_FN(UnmapViewOfFile)((LPCVOID)request);
        lzimpLI_FN(CloseHandle)(hMapping);
        return;
    }

    // 4. Decrypt results from shared memory
    CryptSharedMemory(request);

    // 5. Check results
    if (request->Status != DEEP_STATUS_OK_RT()) {
        SetColor(CLR_RED);
        ConWrite(xorstr_("  [!] Driver scan failed or returned error\n"));
        SetColor(CLR_WHITE);
        lzimpLI_FN(UnmapViewOfFile)((LPCVOID)request);
        lzimpLI_FN(CloseHandle)(hMapping);
        return;
    }

    // 5. Display deep scan results
    ConWrite("\n");
    SetColor(CLR_YELLOW);
    ConWrite(xorstr_("========================================\n"));
    ConWrite(xorstr_("     Deep Scan Results (Ring-0)\n"));
    ConWrite(xorstr_("========================================\n\n"));
    SetColor(CLR_WHITE);

    for (unsigned long i = 0; i < request->TargetCount; i++) {
        DEEP_TARGET* t = &request->Targets[i];

        // Print target header: ProcessName (PID) - module
        ConWrite(xorstr_("[*] "));
        if (t->Pid == evtPid)          ConWrite(xorstr_("EventLog"));
        else if (t->Pid == hdPid)      ConWrite(xorstr_("HD-Player"));
        else if (t->Pid == sysmonPid)  ConWrite(xorstr_("Sysmon"));
        else                           ConWrite(xorstr_("Process"));
        ConWrite(xorstr_(" (PID "));
        ConWriteInt(t->Pid);
        ConWrite(xorstr_(") - "));
        char modA[64];
        int j = 0;
        while (j < 63 && t->ModuleName[j]) {
            modA[j] = (char)t->ModuleName[j];
            j++;
        }
        modA[j] = 0;
        ConWrite(modA);
        ConWrite("\n");

        bool anyTampered = false;

        // Type 1: RO section CoW (WorkingSetEx Shared bit)
        if (t->Flags & DEEP_FLAG_COW_DETECTED) {
            SetColor(CLR_RED);
            ConWrite(xorstr_("  [TAMPERED] CoW Reverse Detect (Type 1)\n"));
            SetColor(CLR_WHITE);
            anyTampered = true;
        }

        // Type 2: Section remap (VAD analysis)
        if (t->Flags & DEEP_FLAG_SECTION_REMAP) {
            SetColor(CLR_RED);
            ConWrite(xorstr_("  [TAMPERED] CoW Reverse Detect (Type 2)\n"));
            SetColor(CLR_WHITE);
            anyTampered = true;
        }

        // Type 3: Syscall stub patched
        if (t->Flags & DEEP_FLAG_STUB_PATCHED) {
            SetColor(CLR_RED);
            ConWrite(xorstr_("  [TAMPERED] Stub Integrity (Type 3)\n"));
            SetColor(CLR_WHITE);
            anyTampered = true;
        }

        // Type 4: .text section CoW (inline hook evidence)
        if (t->Flags & DEEP_FLAG_TEXT_PRIVATE) {
            SetColor(CLR_RED);
            ConWrite(xorstr_("  [TAMPERED] Code Integrity (Type 4)\n"));
            SetColor(CLR_WHITE);
            anyTampered = true;
        }

        // Module hidden from PEB
        if (t->Flags & DEEP_FLAG_MODULE_MISSING) {
            SetColor(CLR_RED);
            ConWrite(xorstr_("  [TAMPERED] Module Hidden\n"));
            SetColor(CLR_WHITE);
            anyTampered = true;
        }

        if (!anyTampered) {
            SetColor(CLR_GREEN);
            ConWrite(xorstr_("  [ INTACT ] No tampering detected\n"));
            SetColor(CLR_WHITE);
        }

        ConWrite("\n");
    }

    // Summary
    bool anyDeepFlag = false;
    for (unsigned long i = 0; i < request->TargetCount; i++) {
        if (request->Targets[i].Flags != 0) anyDeepFlag = true;
    }

    SetColor(CLR_YELLOW);
    ConWrite(xorstr_("========================================\n"));
    if (anyDeepFlag) {
        SetColor(CLR_RED);
        ConWrite(xorstr_("  >> KERNEL SCAN: TAMPERING DETECTED <<\n"));
    } else {
        SetColor(CLR_GREEN);
        ConWrite(xorstr_("  >> KERNEL SCAN: CLEAN <<\n"));
    }
    SetColor(CLR_YELLOW);
    ConWrite(xorstr_("========================================\n"));
    SetColor(CLR_WHITE);

    lzimpLI_FN(UnmapViewOfFile)((LPCVOID)request);
    lzimpLI_FN(CloseHandle)(hMapping);
}

// =============================================
//  Entry point — no CRT
// =============================================

extern "C" int mainCRTStartup() {
    // Console handles from PEB — zero imports
    g_hOut = GetStdOutFromPEB();
    g_hIn  = GetStdInFromPEB();
    if (!g_hOut || g_hOut == (HANDLE)(LONG_PTR)-1) {
        // No console attached — AllocConsole is the only kernel32
        // call we can't replace (requires CSRSS ALPC communication)
        lzimpLI_FN(AllocConsole)();
        g_hOut = GetStdOutFromPEB();
        g_hIn  = GetStdInFromPEB();
    }

    // Init indirect syscall table
    if (!Syscall::Init()) {
        // Can't use ISYSCALL yet — fallback to lazy imports for error
        DWORD w;
        auto msg = xorstr_("[!] Failed to initialize syscall table.\n");
        lzimpLI_FN(WriteConsoleA)(g_hOut, (const void*)msg, (DWORD)slen(msg), &w, (LPVOID)NULL);
        char b[16]; DWORD r;
        lzimpLI_FN(ReadConsoleA)(g_hIn, b, (DWORD)sizeof(b), &r, (PCONSOLE_READCONSOLE_CONTROL)NULL);
        lzimpLI_FN(ExitProcess)(1);
        return 1;
    }

    // Enable VT processing for ANSI color escapes (one-time lazy import)
    {
        DWORD mode = 0;
        lzimpLI_FN(GetConsoleMode)(g_hOut, &mode);
        lzimpLI_FN(SetConsoleMode)(g_hOut, mode | 0x0004); // ENABLE_VIRTUAL_TERMINAL_PROCESSING
    }

    // SeDebugPrivilege via ntdll — no advapi32 dependency
    {
        BOOLEAN oldValue = FALSE;
        lzimpLI_FN(RtlAdjustPrivilege)((ULONG)20, (BOOLEAN)TRUE, (BOOLEAN)FALSE, &oldValue);
    }

    // Anti-debug gate — catch debuggers before any real work
    AntiDebug::Gate();

    // Anti-hook FIRST: detect tampering with ntdll
    // If hooks present, FindWindowA/TerminateProcess may be subverted
    int hookResult = AntiHook::Scan();
    if (hookResult) {
        ISYSCALL(NtTerminateProcess)((HANDLE)-1, (NTSTATUS)0);
        return 0;
    }

    // Anti-debug re-check — catch attach between hook scan and here
    AntiDebug::Gate();

    // Anti-monitoring: detect and kill ProcMon
    // Safe to call now — no hooks intercepting our API calls
    if (AntiMon::IsProcMonActive()) {
        ISYSCALL(NtTerminateProcess)((HANDLE)-1, (NTSTATUS)0);
        return 0;
    }

    // Pre-load DLLs that detection checks will trigger internally
    lzimpLI_FN(LoadLibraryA)(xorstr_("wintrust.dll"));
    lzimpLI_FN(LoadLibraryA)(xorstr_("advapi32.dll"));
    g_OpenGL32Base = (BYTE*)lzimpLI_FN(LoadLibraryA)(xorstr_("opengl32.dll"));
    g_LocalNtdllBase = Syscall::GetNtdllBase();
    DriverMapper::GetExeDirectory(g_ExeDirectory, MAX_PATH);

    // --- Run ALL detection checks BEFORE anti-dump ---
    // This ensures any internally delay-loaded DLLs (bcryptprimitives,
    // rsaenh, imagehlp, cryptsp, cryptbase, etc.) are loaded into the
    // process BEFORE PhantomRemapAll remaps everything to MEM_PRIVATE.

    bool isVm = VmDetect::IsVirtualMachine();

    // Anti-debug gates sprinkled between checks —
    // attacker can't attach mid-scan without being caught
    AntiDebug::Gate();
    RegNoise();
    bool f1 = CheckDefenderExclusion();
    bool f2 = CheckUACDisabled();
    AntiDebug::Gate();
    RegNoise();
    bool f3 = CheckSIPHijack();
    bool f4 = CheckDroppedDll();
    bool f5 = CheckSelfSignature();
    AntiDebug::Gate();
    bool f6 = EventLogDetect::CheckNtWriteFileIntegrity();
    bool f7 = EventLogDetect::CheckNtdllCoWRevert();
    AntiDebug::Gate();
    bool f8 = EventLogDetect::CheckGameTextHooks();
    bool f9 = EventLogDetect::CheckGameRenderIntegrity();

    // --- Anti-dump: full module cloaking ---
    //   1. Phantom remap ALL modules (MEM_IMAGE → MEM_PRIVATE)
    //   2. Erase our EXE's PE headers
    //   3. Cache all lazy import function pointers (while PEB still intact)
    //   4. Empty ALL PEB LDR lists (0 modules visible)
    //   5. Flood memory with decoy PE regions (post-remap)
    AntiDump::PhantomRemapAll();
    AntiDump::EraseHeaders();
    WarmUpLazyImports();
    AntiDump::UnlinkAllFromPEB();
    AntiDump::FloodDecoys();

    // --- Print results (using cached function pointers) ---
    int flagCount = 0;

    if (isVm) {
        SetColor(CLR_YELLOW);
        ConWrite(xorstr_("[!] Virtual environment detected - results may be unreliable\n\n"));
        SetColor(CLR_WHITE);
    }

    SetColor(CLR_YELLOW);
    ConWrite(xorstr_("========================================\n"));
    ConWrite(xorstr_("        bluettw scanner\n"));
    ConWrite(xorstr_("    discord: bluettw.dev\n"));
    ConWrite(xorstr_("========================================\n\n"));
    SetColor(CLR_WHITE);

    ConWrite(xorstr_("[*] Checking Defender exclusion on C:\\...\n"));
    PrintWarn(xorstr_("Defender folder exclusion C:\\"), f1);
    if (f1) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] Checking UAC (EnableLUA)...\n"));
    PrintWarn(xorstr_("UAC disabled (EnableLUA = 0)"), f2);
    if (f2) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] XRC Detect 01...\n"));
    PrintFlag(xorstr_("XRC Detect 01"), f3);
    if (f3) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] XRC Detect 02...\n"));
    PrintFlag(xorstr_("XRC Detect 02"), f4);
    if (f4) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] XRC Detect 03...\n"));
    PrintFlag(xorstr_("XRC Detect 03"), f5);
    if (f5) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] EventLog Usermode Integrity...\n"));
    PrintIntegrity(xorstr_("EventLog Usermode Integrity"), f6);
    if (f6) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] EventLog Kernelmode Integrity...\n"));
    PrintIntegrity(xorstr_("EventLog Kernelmode Integrity"), f7);
    if (f7) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] HD-Player opengl32 Usermode Integrity...\n"));
    PrintIntegrity(xorstr_("HD-Player opengl32 Usermode Integrity"), f8);
    if (f8) flagCount++;
    ConWrite("\n");

    ConWrite(xorstr_("[*] HD-Player opengl32 Kernelmode Integrity...\n"));
    PrintIntegrity(xorstr_("HD-Player opengl32 Kernelmode Integrity"), f9);
    if (f9) flagCount++;
    ConWrite("\n");

    SetColor(CLR_YELLOW);
    ConWrite(xorstr_("========================================\n"));
    ConWrite(xorstr_("  Result: "));
    ConWriteInt(flagCount);
    ConWrite(xorstr_(" / 9 flags triggered\n"));
    ConWrite(xorstr_("========================================\n"));

    if (flagCount >= 3) {
        SetColor(CLR_RED);
        ConWrite(xorstr_("  >> SYSTEM LIKELY COMPROMISED <<\n"));
    }
    else if (flagCount >= 1) {
        SetColor(CLR_YELLOW);
        ConWrite(xorstr_("  >> SUSPICIOUS - investigate further <<\n"));
    }
    else {
        SetColor(CLR_GREEN);
        ConWrite(xorstr_("  >> NO DETECT <<\n"));
    }

    if (f3 || f4 || f5 || f6 || f7 || f8 || f9) {
        ConWrite("\n");
        SetColor(CLR_RED);
        ConWrite(xorstr_("  [!] XRC Detect triggered - apply W.O immediately.\n"));
    }

    // --- Deep Scan prompt ---
    SetColor(CLR_WHITE);
    ConWrite(xorstr_("\n========================================\n"));
    SetColor(CLR_YELLOW);
    ConWrite(xorstr_("  Press ENTER to load driver (deep scan)\n"));
    SetColor(CLR_WHITE);
    ConWrite(xorstr_("========================================\n"));
    ConReadKey();

    RunDeepScan();

    SetColor(CLR_WHITE);
    ConWrite(xorstr_("\nPress ENTER to exit...\n"));
    ConReadKey();

    ISYSCALL(NtTerminateProcess)((HANDLE)-1, (NTSTATUS)0);
    return 0;
}
