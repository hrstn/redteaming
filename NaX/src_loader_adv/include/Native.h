#ifndef NAX_ADV_NATIVE_H
#define NAX_ADV_NATIVE_H

#include <windows.h>

//
// Windows.h provides LIST_ENTRY, NT_TIB, LARGE_INTEGER but not CLIENT_ID on
// all toolchains. Define it ourselves if needed.
//
#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
#endif

//
// Internal NT structures not exposed by the Win32 SDK.
//
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               DllBase;
    PVOID               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    USHORT              LoadCount;
    USHORT              TlsIndex;
    LIST_ENTRY          HashLinks;
    ULONG               TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 BitField;
    PVOID                   Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA           Ldr;
    PVOID                   ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PRTL_CRITICAL_SECTION   FastPebLock;
    PVOID                   AtlThunkSListPtr;
    PVOID                   IFEOKey;
    ULONG                   CrossProcessFlags;
    PVOID                   KernelCallbackTable;
    ULONG                   SystemReserved;
    ULONG                   AtlThunkSListPtr32;
    PVOID                   ApiSetMap;
    union {
        ULONG               TlsExpansionBitmap;
        PVOID               TlsExpansionBitmap_Vista;
    };
    ULONG                   TlsExpansionBitmapBits[32];
    ULONG                   SessionId;
    ULARGE_INTEGER          AppCompatFlags;
    ULARGE_INTEGER          AppCompatFlagsUser;
    PVOID                   pShimData;
    PVOID                   AppCompatInfo;
    UNICODE_STRING          CSDVersion;
    PVOID                   ActivationContextData;
    PVOID                   ProcessAssemblyStorageMap;
    PVOID                   SystemDefaultActivationContextData;
    PVOID                   SystemAssemblyStorageMap;
    SIZE_T                  MinimumStackCommit;
} PEB, *PPEB;

/* Offset-guaranteed TEB.  Only ProcessEnvironmentBlock (0x60) and TlsSlots
 * (0x1480) are read by the loader; the untouched span matches mingw's
 * winternl.h _TEB exactly (12 ptr headers / 399 ptr reserved / 1952 bytes).
 * A hand-enumerated x64 TEB here previously put TlsSlots ~0x2D0 too low,
 * so the TLS egg never resolved and Instance() returned NULL. */
typedef struct _TEB {
    NT_TIB                  NtTib;                     // 0x000
    PVOID                   Pad5[5];                   // 0x038..0x060
    PPEB                    ProcessEnvironmentBlock;   // 0x060
    PVOID                   Reserved2[399];            // 0x068..0xCE0
    BYTE                    Reserved3[1952];           // 0xCE0..0x1480
    PVOID                   TlsSlots[64];              // 0x1480
} TEB, *PTEB;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           QualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE    0x00000040L
#endif

//
// Native function prototypes + typedefs so D_API() works for all of them.
//
NTSTATUS NTAPI NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes );

typedef NTSTATUS (NTAPI *pNtOpenSection)( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES );

NTSTATUS NTAPI NtMapViewOfSection(
    IN HANDLE               SectionHandle,
    IN HANDLE               ProcessHandle,
    IN OUT PVOID           *BaseAddress,
    IN ULONG_PTR            ZeroBits,
    IN SIZE_T               CommitSize,
    IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
    IN OUT PSIZE_T          ViewSize,
    IN DWORD                InheritDisposition,
    IN ULONG                AllocationType,
    IN ULONG                Win32Protect );

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG );

NTSTATUS NTAPI NtUnmapViewOfSection(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress );

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)( HANDLE, PVOID );

NTSTATUS NTAPI NtClose(
    IN HANDLE               Handle );

typedef NTSTATUS (NTAPI *pNtClose)( HANDLE );

NTSTATUS NTAPI NtAllocateVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID           *BaseAddress,
    IN ULONG_PTR            ZeroBits,
    IN OUT PSIZE_T          RegionSize,
    IN ULONG                AllocationType,
    IN ULONG                Protect );

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)( HANDLE, PVOID*, ULONG_PTR, SIZE_T*, ULONG, ULONG );

NTSTATUS NTAPI NtProtectVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID           *BaseAddress,
    IN OUT PSIZE_T          RegionSize,
    IN ULONG                NewProtect,
    OUT PULONG              OldProtect );

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)( HANDLE, PVOID*, SIZE_T*, ULONG, PULONG );

NTSTATUS NTAPI NtQuerySystemInformation(
    IN ULONG                SystemInformationClass,
    IN OUT PVOID            SystemInformation,
    IN ULONG                SystemInformationLength,
    OUT PULONG              ReturnLength OPTIONAL );

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)( ULONG, PVOID, ULONG, PULONG );

NTSTATUS NTAPI LdrLoadDll(
    IN PWCHAR               PathToFile OPTIONAL,
    IN PULONG               Flags OPTIONAL,
    IN PUNICODE_STRING      ModuleFileName,
    OUT PHANDLE             ModuleHandle );

typedef NTSTATUS (NTAPI *pLdrLoadDll)( PWCHAR, PULONG, PUNICODE_STRING, PHANDLE );

PVOID NTAPI RtlAllocateHeap(
    IN PVOID                HeapHandle,
    IN ULONG                Flags,
    IN SIZE_T               Size );

typedef PVOID (NTAPI *pRtlAllocateHeap)( PVOID, ULONG, SIZE_T );

// Win32 wrappers (for non-sensitive use or fallback paths)
BOOL WINAPI VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
typedef BOOL (WINAPI *pVirtualProtect)( LPVOID, SIZE_T, DWORD, PDWORD );

LPVOID WINAPI VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
typedef LPVOID (WINAPI *pVirtualAlloc)( LPVOID, SIZE_T, DWORD, DWORD );

HMODULE WINAPI LoadLibraryExW( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags );
typedef HMODULE (WINAPI *pLoadLibraryExW)( LPCWSTR, HANDLE, DWORD );

BOOL WINAPI GetProcessMitigationPolicy( HANDLE hProcess, PROCESS_MITIGATION_POLICY MitigationPolicy, PVOID lpBuffer, SIZE_T dwLength );
typedef BOOL (WINAPI *pGetProcessMitigationPolicy)( HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T );

BOOL WINAPI SetProcessValidCallTargets( HANDLE hProcess, PVOID VirtualAddress, SIZE_T RegionSize, ULONG NumberOfOffsets, PVOID OffsetInformation );
typedef BOOL (WINAPI *pSetProcessValidCallTargets)( HANDLE, PVOID, SIZE_T, ULONG, PVOID );

HANDLE WINAPI CreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
typedef HANDLE (WINAPI *pCreateThread)( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );

NTSTATUS NTAPI TpAllocWork( PTP_WORK* WorkReturn, PTP_WORK_CALLBACK Callback, PVOID Context, PTP_CALLBACK_ENVIRON CallbackEnv );
typedef NTSTATUS (NTAPI *pTpAllocWork)( PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON );

NTSTATUS NTAPI TpPostWork( PTP_WORK Work );
typedef NTSTATUS (NTAPI *pTpPostWork)( PTP_WORK );

VOID NTAPI TpReleaseWork( PTP_WORK Work );
typedef VOID (NTAPI *pTpReleaseWork)( PTP_WORK );

#ifndef NtCurrentProcess
#define NtCurrentProcess()      ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef NtCurrentThread
#define NtCurrentThread()       ((HANDLE)(LONG_PTR)-2)
#endif

#ifndef NtCurrentPeb
#define NtCurrentPeb()          (NtCurrentTeb()->ProcessEnvironmentBlock)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);   \
    (p)->RootDirectory = (r);                   \
    (p)->Attributes = (a);                       \
    (p)->ObjectName = (n);                      \
    (p)->SecurityDescriptor = (s);                \
    (p)->QualityOfService = NULL;               \
}
#endif

#endif // NAX_ADV_NATIVE_H
