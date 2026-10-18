#include "Common.h"
#include "Constexpr.h"
#include "Dbg.h"

/* Stage-marker output for the debug ladder (NAX_DEBUG=1).
 * Console only: resolves GetStdHandle/WriteFile from kernel32 through the
 * same PEB walk every NAXDBG call - no static state, so nothing in this
 * file ever writes to the loader image (which hosts map PAGE_EXECUTE_READ).
 * The last marker printed is the stage that was about to run. */

#if NAX_DEBUG

typedef HANDLE (WINAPI *pGetStdHandleDbg)( DWORD );
typedef WINBOOL (WINAPI *pWriteFileDbg)( HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID );

FUNC VOID NaxDbg(
    _In_ PVOID Kernel32,
    _In_ PCHAR Tag ) {

    if ( !Kernel32 ) return;

    pGetStdHandleDbg gs = (pGetStdHandleDbg)LdrFunction( Kernel32, HASH_STR("GetStdHandle") );
    pWriteFileDbg    wf = (pWriteFileDbg)LdrFunction( Kernel32, HASH_STR("WriteFile") );
    if ( !gs || !wf )
        return;

    HANDLE h = gs( (DWORD)-11 );    /* STD_OUTPUT_HANDLE */
    if ( !h || h == (HANDLE)-1 )
        return;

    DWORD len = 0;
    while ( Tag[len] ) len++;
    wf( h, Tag, len, &len, NULL );
}

FUNC VOID NaxDbgHex(
    _In_ PVOID  Kernel32,
    _In_ PCHAR  Tag,
    _In_ UINT64 Val ) {

    if ( !Kernel32 ) return;

    pGetStdHandleDbg gs = (pGetStdHandleDbg)LdrFunction( Kernel32, HASH_STR("GetStdHandle") );
    pWriteFileDbg    wf = (pWriteFileDbg)LdrFunction( Kernel32, HASH_STR("WriteFile") );
    if ( !gs || !wf )
        return;

    HANDLE h = gs( (DWORD)-11 );
    if ( !h || h == (HANDLE)-1 )
        return;

    UCHAR buf[64];
    UINT  n   = 0;
    DWORD len = 0;
    while ( Tag[n] && n < 32 ) { buf[n] = (UCHAR)Tag[n]; n++; }
    buf[n++] = ' ';
    for ( INT i = 15; i >= 0; i-- ) {
        UINT d = (UINT)(( Val >> ( i * 4 ) ) & 0xF);
        buf[n++] = (UCHAR)( d < 10 ? '0' + d : 'A' + d - 10 );
    }
    buf[n++] = '\r'; buf[n++] = '\n';
    wf( h, buf, n, &len, NULL );
}

#endif