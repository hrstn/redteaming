/* beacon/include/Defs.h
 * Minimal LDR, PEB, and TEB overlay structs for PEB walk and TEB access.
 * MinGW cross-compile winternl.h hides most _TEB/_PEB fields behind Reserved
 * arrays; these overlays expose the fields at their real x64 offsets.
 * All offsets verified against Windows x64 ABI.
 *
 * NaxCurrentTeb() / NaxCurrentPeb() - thin macros wrapping NtCurrentTeb()
 * (defined in winnt.h, reads GS:[0x30]) cast to our richer overlay types. */

#pragma once
#include <windows.h>

/* ========= [ UNICODE_STRING (PEB/LDR) ] ========= */

typedef struct _NAX_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    DWORD  Pad;      /* x64 alignment: Buffer is at +0x08 */
    PWSTR  Buffer;
} NAX_UNICODE_STRING, *PNAX_UNICODE_STRING;

/* ========= [ LDR_DATA_TABLE_ENTRY (InLoadOrderLinks walk) ] ========= */

typedef struct _NAX_LDR_ENTRY {
    LIST_ENTRY         InLoadOrderLinks;    /* +0x00 */
    LIST_ENTRY         InMemoryOrderLinks;  /* +0x10 */
    LIST_ENTRY         InInitOrderLinks;    /* +0x20 */
    PVOID              DllBase;             /* +0x30 */
    PVOID              EntryPoint;          /* +0x38 */
    ULONG              SizeOfImage;         /* +0x40 */
    ULONG              Reserved;            /* +0x44 */
    NAX_UNICODE_STRING FullDllName;         /* +0x48 */
    NAX_UNICODE_STRING BaseDllName;         /* +0x58 */
    ULONG              Flags;              /* +0x68 */
} NAX_LDR_ENTRY, *PNAX_LDR_ENTRY;

/* ========= [ PEB_LDR_DATA (module list head) ] ========= */

typedef struct _NAX_PEB_LDR_DATA {
    ULONG      Length;                  /* +0x00 */
    BOOLEAN    Initialized;             /* +0x04 */
    BYTE       Pad[3];
    HANDLE     SsHandle;                /* +0x08 */
    LIST_ENTRY InLoadOrderModuleList;   /* +0x10 */
} NAX_PEB_LDR_DATA, *PNAX_PEB_LDR_DATA;

/* ========= [ RTL_USER_PROCESS_PARAMETERS (minimal) ] ========= */
/* Only ImagePathName is exposed - it is at +0x060 in the real struct.
 * Reserved[0x60] pads to the correct offset without naming intervening fields. */

typedef struct _NAX_RTL_USER_PROCESS_PARAMETERS {
    BYTE               Reserved[0x60];
    NAX_UNICODE_STRING ImagePathName;   /* +0x060 (Length/Buffer at +0x060/+0x068) */
} NAX_RTL_USER_PROCESS_PARAMETERS, *PNAX_RTL_USER_PROCESS_PARAMETERS;

/* ========= [ PEB overlay ] ========= */
/*
 * x64 PEB layout (verified):
 *   +0x000  InheritedAddressSpace / ReadImageFileExecOptions  (2 bytes)
 *   +0x002  BeingDebugged                                     (1 byte)
 *   +0x003  BitField + Padding                                (5 bytes)
 *   +0x008  Mutant                                            (8 bytes PVOID)
 *   +0x010  ImageBaseAddress                                  (8 bytes PVOID)
 *   +0x018  Ldr                                               (8 bytes PVOID)
 *   +0x020  ProcessParameters                                 (8 bytes PVOID)
 *   +0x028  SubSystemData                                     (8 bytes)
 *   +0x030  ProcessHeap                                       (8 bytes PVOID)
 *
 * Byte accounting for the Reserved block:
 *   Reserved1[2] (0x00-0x01) + BeingDebugged(0x02) + Reserved2[21](0x03-0x17) = 0x18
 *   → Ldr starts at +0x018 ✓                                                        */

typedef struct _NAX_PEB {
    BYTE                               Reserved1[2];     /* +0x000 */
    BYTE                               BeingDebugged;    /* +0x002 */
    BYTE                               Reserved2[21];    /* +0x003 – fills to +0x017 */
    struct _NAX_PEB_LDR_DATA          *Ldr;              /* +0x018 */
    PNAX_RTL_USER_PROCESS_PARAMETERS   ProcessParameters; /* +0x020 */
    PVOID                              SubSystemData;    /* +0x028 */
    HANDLE                             ProcessHeap;      /* +0x030 */
} NAX_PEB, *PNAX_PEB;

/* ========= [ TEB overlay ] ========= */
/*
 * x64 TEB layout (key fields only):
 *   +0x000  NtTib (NT_TIB, 0x38 bytes) - ArbitraryUserPointer at NtTib+0x028
 *   +0x038  EnvironmentPointer (PVOID)
 *   +0x040  ClientId.UniqueProcess (HANDLE)
 *   +0x048  ClientId.UniqueThread  (HANDLE)
 *   +0x050  ActiveRpcHandle (PVOID)
 *   +0x058  ThreadLocalStoragePointer (PVOID)
 *   +0x060  ProcessEnvironmentBlock (PPEB / PNAX_PEB)                       */

typedef struct _NAX_CLIENT_ID {
    HANDLE UniqueProcess;   /* TEB+0x040 */
    HANDLE UniqueThread;    /* TEB+0x048 */
} NAX_CLIENT_ID;

typedef struct _NAX_TEB {
    NT_TIB         NtTib;                    /* +0x000 (0x38 bytes, ArbitraryUserPointer at +0x028) */
    PVOID          EnvironmentPointer;        /* +0x038 */
    NAX_CLIENT_ID  ClientId;                 /* +0x040 */
    PVOID          ActiveRpcHandle;           /* +0x050 */
    PVOID          ThreadLocalStoragePointer; /* +0x058 */
    PNAX_PEB       ProcessEnvironmentBlock;   /* +0x060 */
    DWORD          LastErrorValue;            /* +0x068 - same as GetLastError(), no import needed */
} NAX_TEB, *PNAX_TEB;

/* NtCurrentTeb() from winnt.h reads GS:[0x30]; cast to our richer type.
 * NaxCurrentPeb() follows the ProcessEnvironmentBlock pointer.            */
#define NaxCurrentTeb()  ( (PNAX_TEB)(PVOID)NtCurrentTeb() )
#define NaxCurrentPeb()  ( NaxCurrentTeb()->ProcessEnvironmentBlock )
