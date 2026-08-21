/*
 * Cenotaph — PEB walk + export-table resolution.
 * Adapted from NaX src_loader/src/Ldr.c (MIT, MaorSabag): same FNV1a
 * walk, same forwarded-export handling.  No API name strings — callers
 * pass FNV1a hashes (HASH_STR at compile time).
 */
#include "Cenotaph.h"

/* resolve a loaded module base from the PEB InLoadOrderModuleList by hash */
FUNC PVOID LdrModulePeb( ULONG Hash ) {
    PCEN_LDR_DATA_TABLE_ENTRY Data  = NULL;
    PLIST_ENTRY               Head  = NULL;
    PLIST_ENTRY               Entry = NULL;

    Head  = &CenPeb()->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = (PCEN_LDR_DATA_TABLE_ENTRY) Entry;

        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash )
            return Data->DllBase;
    }
    return NULL;
}

/* retrieve NT headers for an image base */
static FUNC PIMAGE_NT_HEADERS LdrpImageHeader( PVOID Image ) {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER) Image;
    PIMAGE_NT_HEADERS Nt  = NULL;

    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
        return NULL;

    Nt = (PIMAGE_NT_HEADERS)( U_PTR( Image ) + Dos->e_lfanew );
    if ( Nt->Signature != IMAGE_NT_SIGNATURE )
        return NULL;

    return Nt;
}

/* forwarded export "Module.Function" -> resolve recursively */
static FUNC PVOID LdrpFwdResolve( PCHAR FwdStr ) {
    WCHAR DllNameW[ 64 ] = { 0 };
    PCHAR DotPtr = NULL;
    PCHAR FuncName = NULL;
    PVOID FwdMod  = NULL;
    INT   PfxLen  = 0;
    INT   i       = 0;

    DotPtr = FwdStr;
    while ( *DotPtr && *DotPtr != '.' ) DotPtr++;
    if ( ! *DotPtr ) return NULL;

    FuncName = DotPtr + 1;
    PfxLen   = (INT)( DotPtr - FwdStr );
    if ( PfxLen <= 0 || PfxLen > 59 ) return NULL;

    if ( *FuncName == '#' ) return NULL;   /* ordinal forwarding: unsupported */

    for ( i = 0; i < PfxLen; i++ )
        DllNameW[ i ] = (WCHAR)FwdStr[ i ];

    /* ".dll" as packed UTF-16LE */
    *(UINT64*)( &DllNameW[ PfxLen ] ) = 0x006C006C0064002Eull;
    DllNameW[ PfxLen + 4 ] = L'\0';

    if ( ! ( FwdMod = LdrModulePeb( HashString( DllNameW, ( PfxLen + 4 ) * 2 ) ) ) )
        return NULL;

    return LdrFunction( FwdMod, HashString( FuncName, 0 ) );
}

/* resolve a function pointer by FNV1a hash from a module's export table */
FUNC PVOID LdrFunction( PVOID Library, ULONG Function ) {
    PVOID                   Address    = NULL;
    PIMAGE_NT_HEADERS       Nt         = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDir     = NULL;
    SIZE_T                  ExpDirSize = 0;
    PDWORD                  AddrNames  = NULL;
    PDWORD                  AddrFuncs  = NULL;
    PWORD                   AddrOrdns  = NULL;
    PCHAR                   FuncName   = NULL;
    DWORD                   i          = 0;

    if ( ! Library || ! Function )
        return NULL;

    if ( ! ( Nt = LdrpImageHeader( Library ) ) )
        return NULL;

    ExpDir     = (PIMAGE_EXPORT_DIRECTORY)( U_PTR( Library ) + Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = (PDWORD)( U_PTR( Library ) + ExpDir->AddressOfNames );
    AddrFuncs  = (PDWORD)( U_PTR( Library ) + ExpDir->AddressOfFunctions );
    AddrOrdns  = (PWORD)( U_PTR( Library ) + ExpDir->AddressOfNameOrdinals );

    for ( i = 0; i < ExpDir->NumberOfNames; i++ ) {
        FuncName = (PCHAR)( U_PTR( Library ) + AddrNames[ i ] );

        if ( HashString( FuncName, 0 ) != Function )
            continue;

        Address = (PVOID)( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        /* forwarded export? (address lands inside the export directory) */
        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize ) ) {
            Address = LdrpFwdResolve( (PCHAR) Address );
        }
        break;
    }
    return Address;
}