#include <Common.h>

/* ========= [ PE header helpers ] =========
 *
 * Shared utilities for parsing PE structures. Used by both the
 * module stomp path and the main dispatch logic. */

FUNC PIMAGE_NT_HEADERS NaxPeHeaders( PVOID Base ) {
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Base;
    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
        return NULL;
    PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)( U_PTR( Base ) + Dos->e_lfanew );
    if ( Nt->Signature != IMAGE_NT_SIGNATURE )
        return NULL;
    return Nt;
}

FUNC PIMAGE_SECTION_HEADER NaxFindSection( PIMAGE_NT_HEADERS Nt, ULONG Characteristics ) {
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
    for ( ULONG i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( ( Sec[i].Characteristics & Characteristics ) == Characteristics )
            return &Sec[i];
    }
    return NULL;
}

FUNC PIMAGE_SECTION_HEADER NaxFindSectionByDir( PIMAGE_NT_HEADERS Nt, ULONG DirIndex ) {
    if ( DirIndex >= Nt->OptionalHeader.NumberOfRvaAndSizes )
        return NULL;
    ULONG DirRva = Nt->OptionalHeader.DataDirectory[DirIndex].VirtualAddress;
    if ( !DirRva )
        return NULL;
    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
    for ( ULONG i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( DirRva >= Sec[i].VirtualAddress &&
             DirRva < Sec[i].VirtualAddress + Sec[i].SizeOfRawData )
            return &Sec[i];
    }
    return NULL;
}
