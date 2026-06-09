#pragma once

// =============================================
//  shared.h — Communication between scanner and DeepScan driver
// =============================================

#define DEEP_MAX_TARGETS      4
#define DEEP_SHARED_SIZE      4096

// =============================================
//  Dynamic section name derivation
//  Both kernel and usermode derive the same name
//  from KUSER_SHARED_DATA.BootId (offset 0x2BC)
// =============================================

static __forceinline unsigned long _DeepGetBootId() {
#ifdef _KERNEL_MODE
    return *(volatile unsigned long*)(0xFFFFF78000000000ULL + 0x2BC);
#else
    return *(volatile unsigned long*)(0x7FFE0000ULL + 0x2BC);
#endif
}

static __forceinline void DeriveSectionName(wchar_t* out, int isKernel) {
    unsigned long bootId = _DeepGetBootId();
    unsigned long mixed = bootId ^ 0x4D53CA07u;
    mixed = (mixed >> 16) ^ (mixed * 0x45D9F3Bu);

    const wchar_t* pfx = isKernel
        ? L"\\BaseNamedObjects\\Ds_"
        : L"Global\\Ds_";

    int i = 0;
    while (*pfx) out[i++] = *pfx++;

    const wchar_t hex[] = L"0123456789ABCDEF";
    for (int b = 28; b >= 0; b -= 4)
        out[i++] = hex[(mixed >> b) & 0xF];
    out[i] = L'\0';
}

// =============================================
//  Constant obfuscation (magic, command, status)
//  volatile prevents compiler constant-folding
// =============================================

#define DEEP_OBFMASK  0xCA7F3B12u

static __forceinline unsigned long DeepUnmask(unsigned long obf) {
    volatile unsigned long mask = DEEP_OBFMASK;
    return obf ^ mask;
}

#define DEEP_MAGIC_OBF          (0xB1EE5CA0u ^ DEEP_OBFMASK)
#define DEEP_CMD_SCAN_OBF       (0xD5CA0001u ^ DEEP_OBFMASK)
#define DEEP_STATUS_PENDING_OBF (0u          ^ DEEP_OBFMASK)
#define DEEP_STATUS_OK_OBF      (1u          ^ DEEP_OBFMASK)
#define DEEP_STATUS_ERROR_OBF   (0xDEADu     ^ DEEP_OBFMASK)

#define DEEP_MAGIC_RT()          DeepUnmask(DEEP_MAGIC_OBF)
#define DEEP_CMD_SCAN_RT()       DeepUnmask(DEEP_CMD_SCAN_OBF)
#define DEEP_STATUS_PENDING_RT() DeepUnmask(DEEP_STATUS_PENDING_OBF)
#define DEEP_STATUS_OK_RT()      DeepUnmask(DEEP_STATUS_OK_OBF)
#define DEEP_STATUS_ERROR_RT()   DeepUnmask(DEEP_STATUS_ERROR_OBF)

// Result flags (bitmask — protected by shared memory encryption)
#define DEEP_FLAG_REMAPPED        0x0001
#define DEEP_FLAG_WRONG_PATH      0x0002
#define DEEP_FLAG_NO_SECTION      0x0004
#define DEEP_FLAG_COW_DETECTED    0x0008
#define DEEP_FLAG_PE_TAMPERED     0x0010
#define DEEP_FLAG_MODULE_MISSING  0x0020
#define DEEP_FLAG_TEXT_PRIVATE    0x0040
#define DEEP_FLAG_STUB_PATCHED   0x0080
#define DEEP_FLAG_SECTION_REMAP  0x0100

// =============================================
//  Struct definitions
// =============================================

#pragma pack(push, 8)

typedef struct _DEEP_TARGET {
    unsigned long  Pid;
    wchar_t        ModuleName[64];
    unsigned long  Flags;
    unsigned long  PrivatePages;
    unsigned long  TotalPages;
    unsigned long  TextPrivate;
    unsigned long  TextTotal;
    wchar_t        SectionPath[260];
    unsigned long  MemType;
    unsigned long  DbgWsExStatus;
    unsigned long  DbgWsExValid;
    unsigned long  DbgWsExLowShare;
    unsigned long  DbgWsExSample;
} DEEP_TARGET;

typedef struct _DEEP_SCAN_REQUEST {
    unsigned long  Magic;
    unsigned long  Command;
    unsigned long  TargetCount;
    unsigned long  Status;
    DEEP_TARGET    Targets[DEEP_MAX_TARGETS];
} DEEP_SCAN_REQUEST;

#pragma pack(pop)

// =============================================
//  Shared memory XOR encryption
//  Key derived from BootId — identical on both sides
//  Encrypts entire struct (symmetric XOR)
// =============================================

#define DEEP_CRYPT_KEY_SIZE  16

static __forceinline void _DeepDeriveKey(unsigned char key[DEEP_CRYPT_KEY_SIZE]) {
    unsigned long seed = _DeepGetBootId() ^ 0x7A3C9E1Fu;
    for (int i = 0; i < DEEP_CRYPT_KEY_SIZE; i++) {
        seed = seed * 1103515245u + 12345u;
        key[i] = (unsigned char)(seed >> 16);
    }
}

static __forceinline void CryptSharedMemory(DEEP_SCAN_REQUEST* req) {
    unsigned char key[DEEP_CRYPT_KEY_SIZE];
    _DeepDeriveKey(key);

    unsigned char* data = (unsigned char*)req;
    unsigned long  size = sizeof(DEEP_SCAN_REQUEST);

    for (unsigned long i = 0; i < size; i++)
        data[i] ^= key[i % DEEP_CRYPT_KEY_SIZE];
}
