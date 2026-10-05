#ifndef NAX_ADV_MACROS_H
#define NAX_ADV_MACROS_H

#include <windows.h>

#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
#define EXTERN_C    extern "C"

#define C_PTR( x )  ( ( PVOID )    ( x ) )
#define U_PTR( x )  ( ( UINT_PTR ) ( x ) )
#define B_PTR( x )  ( ( PBYTE )    ( x ) )
#define W_PTR( x )  ( ( PWCHAR )   ( x ) )

#define C_DEF32( x ) ( *( ( ULONG* ) ( x ) ) )
#define C_DEF64( x ) ( *( ( UINT64* ) ( x ) ) )

#define MmCopy( dst, src, len ) __builtin_memcpy( (dst), (src), (len) )
#define MmSet( dst, val, len )  __builtin_memset( (dst), (val), (len) )
#define MmZero( dst, len )      __builtin_memset( (dst), 0, (len) )

#define ALIGN_UP( size, align ) ( ( (size) + ((align) - 1) ) & ~( (SIZE_T)(align) - 1 ) )
#define LDR_PAGE_SIZE           0x1000u

#define D_API( x )  __typeof__( x ) * x;

#define MOD( x )          Instance()->Modules.x
#define API( x )          Instance()->Win32.x
#define SCAPI( x )        Instance()->Syscalls.x
#define RESOLVE( x, y )   ( API(x) = (__typeof__(x)*)LdrFunction( MOD(y), HASH_STR(#x) ) )

#define HDR_U32( h, off )   C_DEF32( C_PTR( U_PTR(h) + (off) ) )
#define HDR_WSTR( h, off )  W_PTR( U_PTR(h) + (off) )
#define LOADER_END()        C_PTR( U_PTR(Instance()->Base.Buffer) + Instance()->Base.Length )

//
// TLS egghunter retrieval.
// The INSTANCE pointer is stored in the TLS slot immediately following the slot
// that contains NtCurrentPeb().
//
static __inline__ PVOID __TlsFindInstance( void ) {
    PVOID peb = C_PTR( NtCurrentPeb() );
    PTEB  teb = NtCurrentTeb();
    for ( UINT32 i = 0; i < 63; i++ ) {
        if ( teb->TlsSlots[i] == peb )
            return teb->TlsSlots[i + 1];
    }
    return C_PTR( 0 );
}

#define STARDUST_INSTANCE  PINSTANCE __LocalInstance = (PINSTANCE)__TlsFindInstance();
#define Instance()         __LocalInstance

#endif // NAX_ADV_MACROS_H
