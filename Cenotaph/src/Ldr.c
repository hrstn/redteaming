/*
 * Tiny PEB-walk module / export resolver.
 */
#include "Cenotaph.h"

extern "C" PVOID CenLdrModulePeb( ULONG Hash ) {
    PCEN_PEB           peb = CenPeb();
    PCEN_PEB_LDR_DATA  ldr = peb ? peb->Ldr : NULL;
    PLIST_ENTRY        head = ldr ? &ldr->InLoadOrderModuleList : NULL;
    PLIST_ENTRY        cur  = head ? head->Flink : NULL;

    if ( ! peb || ! ldr || ! head || ! cur )
        return NULL;

    while ( cur != head ) {
        PCEN_LDR_DATA_TABLE_ENTRY ent = (PCEN_LDR_DATA_TABLE_ENTRY)cur;
        if ( ent->BaseDllName.Buffer && ent->BaseDllName.Length ) {
            if ( CenHashString( ent->BaseDllName.Buffer, ent->BaseDllName.Length ) == Hash )
                return ent->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* Resolve a forwarded export ("KERNELBASE.CreateFileW"): split module
 * prefix from function name, hash the prefix + ".dll" the same way the
 * module walker hashes BaseDllName, then recurse.  Ordinal forwarding
 * ("Module.#N") returns NULL. */
static PVOID CenFwdResolve( PCHAR FwdStr ) {
    WCHAR DllNameW[ 64 ] = { 0 };
    PCHAR DotPtr = FwdStr;
    PCHAR FuncName;
    PVOID FwdMod;
    INT   PfxLen, i;

    while ( *DotPtr && *DotPtr != '.' ) DotPtr++;
    if ( ! *DotPtr ) return NULL;
    FuncName = DotPtr + 1;
    PfxLen   = (INT)( DotPtr - FwdStr );
    if ( PfxLen <= 0 || PfxLen > 59 ) return NULL;
    if ( *FuncName == '#' ) return NULL;

    for ( i = 0; i < PfxLen; i++ ) DllNameW[i] = (WCHAR)FwdStr[i];
    *(UINT64 *)( &DllNameW[ PfxLen ] ) = 0x006C006C0064002Eull;   /* ".dll" UTF-16LE */
    DllNameW[ PfxLen + 4 ] = L'\0';

    FwdMod = CenLdrModulePeb( CenHashString( DllNameW, ( PfxLen + 4 ) * 2 ) );
    if ( ! FwdMod ) return NULL;
    return CenLdrFunction( FwdMod, CenHashString( FuncName, 0 ) );
}

extern "C" PVOID CenLdrFunction( PVOID Library, ULONG Function ) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Library;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD names, funcs;
    PWORD  ords;
    DWORD  i, n;

    if ( ! Library || dos->e_magic != IMAGE_DOS_SIGNATURE )
        return NULL;

    nt = (PIMAGE_NT_HEADERS)( (PUCHAR)Library + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE )
        return NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY)( (PUCHAR)Library +
        nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    n = exp->NumberOfNames;
    names = (PDWORD)( (PUCHAR)Library + exp->AddressOfNames );
    funcs = (PDWORD)( (PUCHAR)Library + exp->AddressOfFunctions );
    ords  = (PWORD)( (PUCHAR)Library + exp->AddressOfNameOrdinals );

    for ( i = 0; i < n; i++ ) {
        PCHAR name = (PCHAR)( (PUCHAR)Library + names[i] );
        if ( CenHashString( name, 0 ) == Function ) {
            PVOID fn = (PVOID)( (PUCHAR)Library + funcs[ ords[i] ] );
            /* forwarder? resolve the forwarding string instead of failing */
            if ( (PUCHAR)fn >= (PUCHAR)exp && (PUCHAR)fn < (PUCHAR)exp +
                 nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size ) {
                return CenFwdResolve( (PCHAR)fn );
            }
            return fn;
        }
    }
    return NULL;
}
