#ifndef NAX_ADV_DBG_H
#define NAX_ADV_DBG_H

#include "Common.h"

#if NAX_DEBUG
FUNC VOID NaxDbg( PVOID Kernel32, PCHAR Tag );
FUNC VOID NaxDbgHex( PVOID Kernel32, PCHAR Tag, UINT64 Val );
#define NAXDBG( k32, tag ) NaxDbg( (k32), (tag) )
#define NAXDBGX( k32, tag, v ) NaxDbgHex( (k32), (tag), (UINT64)(v) )
#else
#define NAXDBG( k32, tag ) ( (VOID)0 )
#define NAXDBGX( k32, tag, v ) ( (VOID)0 )
#endif

#endif // NAX_ADV_DBG_H