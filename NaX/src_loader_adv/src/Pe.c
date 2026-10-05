#include "Common.h"
#include "Loader.h"

FUNC PIMAGE_NT_HEADERS NaxPeHeaders(
    _In_ PVOID Base ) {

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
    if ( !Base || dos->e_magic != IMAGE_DOS_SIGNATURE ) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)( U_PTR(Base) + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return NULL;

    return nt;
}

FUNC PIMAGE_SECTION_HEADER NaxFindSection(
    _In_ PIMAGE_NT_HEADERS Nt,
    _In_ ULONG             Characteristics ) {

    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
    for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( ( Sec[i].Characteristics & Characteristics ) == Characteristics ) {
            return &Sec[i];
        }
    }
    return NULL;
}

FUNC PIMAGE_SECTION_HEADER NaxFindSectionByDir(
    _In_ PIMAGE_NT_HEADERS Nt,
    _In_ DWORD             Directory ) {

    DWORD dirRva = Nt->OptionalHeader.DataDirectory[ Directory ].VirtualAddress;
    if ( !dirRva ) return NULL;

    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
    for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( dirRva >= Sec[i].VirtualAddress &&
             dirRva <  Sec[i].VirtualAddress + Sec[i].Misc.VirtualSize ) {
            return &Sec[i];
        }
    }
    return NULL;
}
