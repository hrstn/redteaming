/* beacon/src/Core/Helpers.c
 * Shared helper functions - deduplicated from per-module static copies.
 * All PIC-safe (FUNC section placement, no CRT). */

#include "Nax.h"

/* ========= [ string length ] ========= */

FUNC UINT32 NaxStrLen( const PCHAR str ) {
    UINT32 n = 0;
    while ( str && str[n] ) n++;
    return n;
}

FUNC UINT32 NaxWcharLen( const PWCHAR wstr ) {
    UINT32 n = 0;
    while ( wstr[n] ) n++;
    return n;
}

/* ========= [ Win32 error writer ] ========= */

FUNC VOID NaxWriteWin32ErrCode( PBYTE out, UINT32* out_len, DWORD code ) {
    if ( *out_len >= 4 ) {
        out[0] = (BYTE)code;
        out[1] = (BYTE)( code >> 8 );
        out[2] = (BYTE)( code >> 16 );
        out[3] = (BYTE)( code >> 24 );
        *out_len = 4;
    } else {
        *out_len = 0;
    }
}

/* ========= [ text append helpers ] ========= */

FUNC UINT32 NaxAppendStr( PCHAR dst, UINT32 off, UINT32 cap, const CHAR* src ) {
    while ( *src && off < cap )
        dst[off++] = *src++;
    return off;
}

FUNC UINT32 NaxAppendWStr( PCHAR dst, UINT32 off, UINT32 cap, const WCHAR* src ) {
    while ( *src && off < cap )
        dst[off++] = (CHAR)*src++;
    return off;
}

FUNC UINT32 NaxAppendInt( PCHAR dst, UINT32 off, UINT32 cap, UINT32 value ) {
    CHAR tmp[12];
    UINT32 len = NaxUToStr( value, tmp );
    for ( UINT32 i = 0; i < len && off < cap; i++ )
        dst[off++] = tmp[i];
    return off;
}

FUNC UINT32 NaxAppendPtr( PCHAR dst, UINT32 off, UINT32 cap, UINT_PTR val ) {
    static const char hex[] D_SEC( Bd ) = "0123456789abcdef";
    if ( off + 2 >= cap ) return off;
    dst[off++] = '0';
    dst[off++] = 'x';
    for ( INT i = ( sizeof( UINT_PTR ) * 2 ) - 1; i >= 0 && off < cap; i-- )
        dst[off++] = hex[ ( val >> ( i * 4 ) ) & 0xF ];
    return off;
}

/* ========= [ W2.2 kill date ] ========= */

/* TRUE once the compile-time kill date has passed. KillDate is unix UTC
 * seconds, 0 = disabled. GetSystemTimeAsFileTime is a resolved Kernel32
 * pointer (100ns since 1601 -> subtract the epoch offset). */
FUNC BOOL NaxKillExpired( PNAX_INSTANCE Nax ) {
    if ( ! Nax->Config.KillDate || ! Nax->Kernel32.GetSystemTimeAsFileTime )
        return FALSE;
    FILETIME ft;
    Nax->Kernel32.GetSystemTimeAsFileTime( &ft );
    UINT64 unix_sec = ( ( (UINT64)ft.dwHighDateTime << 32 ) | ft.dwLowDateTime ) / 10000000u;
    return ( unix_sec >= (UINT64)Nax->Config.KillDate + 11644473600u );
}

/* Wipe the instance-private span (session id, AES key, C2 URL, profile) and
 * exit the host process. Called by the transport loops when NaxKillExpired. */
FUNC VOID NaxKillNow( PNAX_INSTANCE Nax ) {
    MmZero( (PBYTE)Nax->SessionId, NAX_PRIV_LEN( Nax ) );
    Nax->Kernel32.ExitProcess( 0 );
}
