#pragma once

// Syscall stub integrity check
// Verifies NtWriteFile and NtTraceEvent stubs in ntdll haven't been patched
// Depends on: resolve.hpp, remote.hpp

static void CheckCriticalStubs(PEPROCESS Process, PVOID moduleBase, DEEP_TARGET* Target) {
    IMAGE_DOS_HEADER dos;
    if (!NT_SUCCESS(SafeReadRemote(Process, moduleBase, &dos, sizeof(dos)))) return;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return;

    IMAGE_NT_HEADERS64 nt;
    if (!NT_SUCCESS(SafeReadRemote(Process, (PVOID)((ULONG_PTR)moduleBase + dos.e_lfanew), &nt, sizeof(nt)))) return;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return;

    ULONG expRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return;

    IMAGE_EXPORT_DIRECTORY expDir;
    if (!NT_SUCCESS(SafeReadRemote(Process, (PVOID)((ULONG_PTR)moduleBase + expRva), &expDir, sizeof(expDir)))) return;

    ULONG numNames = expDir.NumberOfNames;
    if (numNames > 4096) numNames = 4096;

    for (ULONG i = 0; i < numNames; i++) {
        ULONG nameRva;
        if (!NT_SUCCESS(SafeReadRemote(Process,
            (PVOID)((ULONG_PTR)moduleBase + expDir.AddressOfNames + i * 4), &nameRva, 4))) continue;

        char prefix[2] = {};
        SafeReadRemote(Process, (PVOID)((ULONG_PTR)moduleBase + nameRva), prefix, 2);
        if (prefix[0] > 'N') break;
        if (prefix[0] != 'N' || prefix[1] != 't') continue;

        char name[20] = {};
        SafeReadRemote(Process, (PVOID)((ULONG_PTR)moduleBase + nameRva), name, 19);

        BOOLEAN isTarget =
            (name[2]=='W' && name[3]=='r' && name[4]=='i' && name[5]=='t' &&
             name[6]=='e' && name[7]=='F' && name[8]=='i' && name[9]=='l' && name[10]=='e' && name[11]==0);

        if (!isTarget)
            isTarget =
                (name[2]=='T' && name[3]=='r' && name[4]=='a' && name[5]=='c' &&
                 name[6]=='e' && name[7]=='E' && name[8]=='v' && name[9]=='e' && name[10]=='n' && name[11]=='t' && name[12]==0);

        if (!isTarget) continue;

        USHORT ordinal;
        if (!NT_SUCCESS(SafeReadRemote(Process,
            (PVOID)((ULONG_PTR)moduleBase + expDir.AddressOfNameOrdinals + i * 2), &ordinal, 2))) continue;

        ULONG funcRva;
        if (!NT_SUCCESS(SafeReadRemote(Process,
            (PVOID)((ULONG_PTR)moduleBase + expDir.AddressOfFunctions + ordinal * 4), &funcRva, 4))) continue;

        UCHAR stub[8] = {};
        SafeReadRemote(Process, (PVOID)((ULONG_PTR)moduleBase + funcRva), stub, 8);

        // Expected pattern: 4C 8B D1 B8 <syscall_id> — any deviation = patched
        if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8)
            Target->Flags |= DEEP_FLAG_STUB_PATCHED;
    }
}
