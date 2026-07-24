#include <Common.h>
#include <Constexpr.h>

#define TLS_SEARCH_LIMIT  20

EXTERN_C FUNC VOID PreMain(
    PVOID Param
) {
    INSTANCE Stardust = { 0 };
    PVOID    Heap     = { 0 };
    PVOID    Inst     = { 0 };

    MmZero( & Stardust, sizeof( Stardust ) );

    Heap = NtCurrentPeb()->ProcessHeap;

    Stardust.Base.Buffer = StRipStart();
    Stardust.Base.Length = U_PTR( StRipEnd() ) - U_PTR( Stardust.Base.Buffer );

    /* ========= [ resolve ntdll + kernel32 ] ========= */

    if ( ! ( Stardust.Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) )
        return;
    if ( ! ( Stardust.Win32.RtlAllocateHeap = LdrFunction( Stardust.Modules.Ntdll, HASH_STR( "RtlAllocateHeap" ) ) ) )
        return;

    if ( ! ( Stardust.Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) )
        return;
    if ( ! ( Stardust.Win32.TlsAlloc    = LdrFunction( Stardust.Modules.Kernel32, HASH_STR( "TlsAlloc"    ) ) ) ||
         ! ( Stardust.Win32.TlsSetValue = LdrFunction( Stardust.Modules.Kernel32, HASH_STR( "TlsSetValue" ) ) ) ||
         ! ( Stardust.Win32.TlsFree     = LdrFunction( Stardust.Modules.Kernel32, HASH_STR( "TlsFree"     ) ) )
    ) {
        return;
    }

    /* ========= [ find two consecutive TLS slots (egghunter storage) ] ========= */

    DWORD  slots[ TLS_SEARCH_LIMIT ] = { 0 };
    UINT32 slotCount = 0;
    DWORD  eggSlot   = TLS_OUT_OF_INDEXES;
    DWORD  instSlot  = TLS_OUT_OF_INDEXES;

    for ( UINT32 i = 0; i < TLS_SEARCH_LIMIT; i++ ) {
        slots[ i ] = Stardust.Win32.TlsAlloc();
        if ( slots[ i ] == TLS_OUT_OF_INDEXES )
            break;
        slotCount++;

        if ( i > 0 && slots[ i ] == slots[ i - 1 ] + 1 ) {
            eggSlot  = slots[ i - 1 ];
            instSlot = slots[ i ];
            break;
        }
    }

    if ( eggSlot == TLS_OUT_OF_INDEXES )
        return;

    /* free non-consecutive slots we allocated during the search */
    for ( UINT32 i = 0; i < slotCount; i++ ) {
        if ( slots[ i ] != eggSlot && slots[ i ] != instSlot )
            Stardust.Win32.TlsFree( slots[ i ] );
    }

    /* ========= [ allocate INSTANCE on heap, store via TLS ] ========= */

    Inst = Stardust.Win32.RtlAllocateHeap( Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) );
    if ( ! Inst )
        return;

    /* egg = NtCurrentPeb() address, instance pointer in next slot */
    Stardust.Win32.TlsSetValue( eggSlot,  (LPVOID)NtCurrentPeb() );
    Stardust.Win32.TlsSetValue( instSlot, Inst );

    MmCopy( Inst, & Stardust, sizeof( INSTANCE ) );
    MmZero( & Stardust, sizeof( INSTANCE ) );

    Main( Param );
}
