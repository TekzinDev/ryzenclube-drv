;; =============================================
;;  IndirectSyscall.asm — x64 MASM stub
;;
;;  DoIndirectSyscall:
;;    1. mov r10, rcx        (NT syscall convention)
;;    2. mov eax, [g_SyscallSsn]   (SSN from resolver)
;;    3. jmp [g_SyscallGadget]      (syscall;ret inside ntdll)
;;
;;  The JMP to a gadget inside ntdll means:
;;    - Return address on kernel stack points into ntdll
;;    - Stack-based syscall origin checks pass
;;    - No syscall instruction in our module's .text section
;; =============================================

.DATA

PUBLIC g_SyscallSsn
PUBLIC g_SyscallGadget

g_SyscallSsn    DD 0
g_SyscallGadget DQ 0

.CODE

PUBLIC DoIndirectSyscall

DoIndirectSyscall PROC
    mov r10, rcx                        ; 1st arg -> r10 (NT convention)
    mov eax, DWORD PTR [g_SyscallSsn]  ; syscall number
    jmp QWORD PTR [g_SyscallGadget]    ; indirect jump -> syscall;ret in ntdll
DoIndirectSyscall ENDP

;; =============================================
;;  __chkstk — stack probe for large allocations
;;  MSVC emits calls to this when a function needs
;;  more than 4KB of stack. Probes each page so the
;;  guard page mechanism can extend the stack.
;;  rax = bytes needed (set by compiler before call)
;; =============================================

PUBLIC __chkstk

__chkstk PROC
    sub     rsp, 10h
    mov     QWORD PTR [rsp], r10
    mov     QWORD PTR [rsp+8], r11
    xor     r11, r11
    lea     r10, [rsp+18h]          ; original rsp before our sub
    sub     r10, rax                ; target stack pointer
    cmovb   r10, r11                ; clamp to 0 on underflow
    mov     r11, QWORD PTR gs:[10h] ; stack limit (lowest committed page)
    cmp     r10, r11
    jge     chkstk_done             ; already committed — nothing to do
chkstk_loop:
    sub     r11, 1000h              ; probe one page down
    test    DWORD PTR [r11], r11d   ; touch the page (trigger guard page)
    cmp     r10, r11
    jl      chkstk_loop             ; keep probing until we reach target
chkstk_done:
    mov     r10, QWORD PTR [rsp]
    mov     r11, QWORD PTR [rsp+8]
    add     rsp, 10h
    ret
__chkstk ENDP

END
