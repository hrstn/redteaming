#include "Common.h"
#include "Constexpr.h"

FUNC BOOL NaxAntiAnalysis( VOID ) {
    STARDUST_INSTANCE

    // 1) Debugger check via PEB
    if ( NtCurrentPeb()->BeingDebugged )
        return FALSE;

    ULONG ntGlobal = *(PULONG)( (PBYTE)NtCurrentPeb() + 0xBC );
    if ( (ntGlobal & 0x70) != 0 )
        return FALSE;

    // 2) Processor count via NtQuerySystemInformation (class 0 = SystemBasicInformation)
    if ( API(NtQuerySystemInformation) ) {
        SYSTEM_INFO si = { 0 };
        NTSTATUS st = ( (pNtQuerySystemInformation)API(NtQuerySystemInformation) )(
            0, &si, sizeof(si), NULL );
        if ( NT_SUCCESS(st) && si.dwNumberOfProcessors < 2 )
            return FALSE;
    }

    return TRUE;
}
