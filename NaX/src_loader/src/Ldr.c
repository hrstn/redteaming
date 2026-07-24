#include <Common.h>

/*!
 * @brief
 *  resolve module from peb
 *
 * @param Buffer
 *  Buffer: either string or hash
 *
 * @param Hashed
 *  is the Buffer a hash value
 *
 * @return
 *  module base pointer
 */
FUNC PVOID LdrModulePeb(
    _In_ ULONG Hash
) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base pointer to retrieve header from
 *
 * @return
 *  pointer to Nt Header
 */
FUNC PIMAGE_NT_HEADERS LdrpImageHeader(
        _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

/* ========= [ forwarded export resolution ] =========
 *
 * Forwarding strings have the form "ModuleName.FunctionName"
 * (e.g. "KERNELBASE.VirtualAlloc").  We append ".dll", hash the result
 * for PEB lookup, then recurse into LdrFunction on the target module.
 *
 * Ordinal forwarding ("ModuleName.#N") returns NULL - not implemented.  */
FUNC PVOID LdrpFwdResolve( _In_ PCHAR FwdStr ) {
    WCHAR DllNameW[ 64 ] = { 0 };
    PCHAR DotPtr         = { 0 };
    PCHAR FuncName       = { 0 };
    PVOID FwdMod         = { 0 };
    INT   PfxLen         = { 0 };
    INT   i              = { 0 };

    /* find the '.' separating module prefix from function name */
    DotPtr = FwdStr;
    while ( *DotPtr && *DotPtr != '.' ) DotPtr++;
    if ( ! *DotPtr ) return NULL;

    FuncName = DotPtr + 1;
    PfxLen   = (INT)( DotPtr - FwdStr );
    if ( PfxLen <= 0 || PfxLen > 59 ) return NULL;

    /* ordinal forwarding ("Module.#N") - not implemented */
    if ( *FuncName == '#' ) return NULL;

    for ( i = 0; i < PfxLen; i++ ) DllNameW[ i ] = (WCHAR)FwdStr[ i ];

    /* ".dll" as packed UTF-16LE - avoids 4x mov-word-immediate pattern */
    *(UINT64 *)( &DllNameW[ PfxLen ] ) = 0x006C006C0064002Eull;
    DllNameW[ PfxLen + 4 ] = L'\0';

    /* locate target module in PEB then recurse */
    if ( ! ( FwdMod = LdrModulePeb( HashString( DllNameW, ( PfxLen + 4 ) * 2 ) ) ) ) return NULL;

    return LdrFunction( FwdMod, HashString( FuncName, 0 ) );
}

FUNC PVOID LdrFunction(
    _In_ PVOID Library,
    _In_ ULONG Function
) {
    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };

    //
    // sanity check arguments
    //
    if ( ! Library || ! Function ) {
        return NULL;
    }

    //
    // retrieve header of library
    //
    if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
        return NULL;
    }

    //
    // parse the header export address table
    //
    ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
    AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

    //
    // iterate over export address table director
    //
    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
        //
        // retrieve function name
        //
        FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

        //
        // hash function name from Iat and
        // check the function name is what we are searching for.
        // if not found keep searching.
        //
        if ( HashString( FuncName, 0 ) != Function ) {
            continue;
        }

        //
        // resolve function pointer
        //
        Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        /* check if this is a forwarded export (Address falls inside ExpDir) */
        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            /* forwarding string points to the target module - resolve it */
            Address = LdrpFwdResolve( ( PCHAR ) Address );
        }

        break;
    }

    return Address;
}