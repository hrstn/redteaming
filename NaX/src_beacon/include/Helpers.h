/* beacon/include/Helpers.h
 * Shared helper functions - deduplicated from per-module static copies. */

#pragma once
#include "Macros.h"
#include "Instance.h"

FUNC UINT32 NaxStrLen( const PCHAR s );
FUNC UINT32 NaxWcharLen( const PWCHAR s );
FUNC VOID   NaxWriteWin32ErrCode( PBYTE out, UINT32* out_len, DWORD code );
FUNC UINT32 NaxAppendStr( PCHAR dst, UINT32 off, UINT32 cap, const CHAR* src );
FUNC UINT32 NaxAppendWStr( PCHAR dst, UINT32 off, UINT32 cap, const WCHAR* src );
FUNC UINT32 NaxAppendInt( PCHAR dst, UINT32 off, UINT32 cap, UINT32 v );
FUNC UINT32 NaxAppendPtr( PCHAR dst, UINT32 off, UINT32 cap, UINT_PTR val );
