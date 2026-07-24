#ifndef NAX_LOADER_H
#define NAX_LOADER_H

#include <Common.h>

/* ========= [ Pe.c ] ========= */

PIMAGE_NT_HEADERS NaxPeHeaders( PVOID Base );
PIMAGE_SECTION_HEADER NaxFindSection( PIMAGE_NT_HEADERS Nt, ULONG Characteristics );
PIMAGE_SECTION_HEADER NaxFindSectionByDir( PIMAGE_NT_HEADERS Nt, ULONG DirIndex );

/* ========= [ Stomp.c ] ========= */

#if NAX_STOMP_MODE == NAX_STOMP_MODULE
VOID NaxPatchLdr( PVOID DllBase );
PVOID NaxModuleStomp(
    _In_ PVOID   HdrPtr,
    _In_ PVOID   BeaconSrc,
    _In_ ULONG   BeaconSize,
    _In_ PVOID   PdataSrc,
    _In_ ULONG   PdataSize,
    _In_ PVOID   XdataSrc,
    _In_ ULONG   XdataSize,
    _In_ ULONG   OrigTextRva,
    _In_ PWCHAR  DllName );
#endif

/* ========= [ Exec.c ] ========= */

#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
VOID NaxExecThreadPool( PVOID Entry );
#elif NAX_EXEC_MODE == NAX_EXEC_THREAD
VOID NaxExecThread( PVOID Entry );
#endif

/* ========= [ Main.c ] ========= */

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
PVOID NaxAllocExec( _In_ PVOID BeaconSrc, _In_ ULONG BeaconSize );
#endif

#endif /* NAX_LOADER_H */
