# ryzenclube-drv

Kernel-mode forensic scanner for detecting cheat activity on Windows. Used by **Ryzen Clube** for player integrity verification.

## Overview

Two-component architecture:

| Component | Description |
|---|---|
| `ryzenclube-drv/` | Usermode scanner — registry, file, signature and hook checks |
| `ryzenclube-drv-sys/` | Kernel driver — ring-0 memory integrity checks via shared memory |

The usermode scanner maps the kernel driver at runtime using a vulnerable driver (BYOVD) since the project does not yet have an EV code-signing certificate.

## Detection Capabilities

### Usermode Checks
| Check | Description |
|---|---|
| Defender Exclusion | Detects `C:\` added to Windows Defender exclusion paths |
| UAC | Detects `EnableLUA = 0` (UAC disabled) |
| SIP Hijack | Detects `CryptSIPDllVerifyIndirectData` registry hijack |
| Dropped DLL | Detects `DWriteCore.dll` in `System32` (known cheat artifact) |
| Self Signature | Verifies own binary signature integrity |
| EventLog Integrity | Detects usermode hooks in EventLog service's `ntdll.dll` |
| EventLog CoW Revert | Detects kernel-level ntdll manipulation via CoW analysis |
| HD-Player Hooks | Detects hooks in `opengl32.dll` of HD-Player (Android emulator) |
| HD-Player Kernel Integrity | Kernel-mode `opengl32.dll` integrity check |

### Kernel Driver Checks (ring-0)
| Check | Description |
|---|---|
| Memory Type | Detects `MEM_IMAGE` → `MEM_PRIVATE` remapping |
| Section Path | Validates module is backed by expected file on disk |
| CoW Detection | WorkingSetEx Shared-bit analysis — detects copy-on-write page modifications |
| PE Integrity | Validates PE header structure in remote process memory |
| VAD Analysis | Walks VAD tree to detect phantom section remaps via ControlArea |
| Stub Integrity | Verifies `NtWriteFile` and `NtTraceEvent` syscall stubs in ntdll |
| Module Visibility | Detects modules hidden from PEB LDR |

## Anti-Reversing

The scanner protects itself from being analyzed and bypassed:

- **AntiDebug** — detects and terminates on debugger attach
- **AntiHook** — detects ntdll hooks before any scan logic runs
- **AntiDump** — phantom remap + PEB unlink + header erase to resist memory dumping
- **AntiMon** — detects and terminates on ProcMon presence
- **LLVM Obfuscation** — compiled with LLVM obfuscator pass
- **XorStr** — string literals obfuscated at compile time
- **Indirect Syscalls** — all NT calls via indirect syscall stubs (no IAT entries)
- **Lazy Import** — API resolution at runtime, no static imports
- **Registry Noise** — decoy registry reads to pollute CmRegisterCallback logs

## Tech Stack

- C++ (no CRT), WDK (kernel driver)
- Indirect syscalls + lazy import for zero static IAT
- BYOVD via `iqvw64e.sys` for unsigned driver loading
- LLVM obfuscator for binary hardening
- Shared memory section for usermode ↔ kernel communication

## Build

Open `ryzenclube-drv.sln` in Visual Studio 2022 with WDK installed. Build `Release|x64`.

```
build.bat           — MSVC release build
build_clang.bat     — Clang/LLVM build (with obfuscation)
build_deepscan.bat  — Kernel driver build
```
