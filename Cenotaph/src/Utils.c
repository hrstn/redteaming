/*
 * Cenotaph — runtime FNV1a-32 (case-insensitive), wide-capable.
 * Verbatim from NaX src_loader/src/Utils.c (MIT, MaorSabag): the null-
 * handling in the wide path (`if(!*Ptr) ++Ptr;` then hashing the stale
 * Char and a trailing `++Ptr`) is load-bearing — verified empirically it
 * reproduces H_MODULE_NTDLL (0x318a7963) and H_MODULE_KERNEL32
 * (0x04a1a06a) exactly.  Do NOT "clean" it to a skip-and-continue form;
 * that yields different hashes and module resolution silently fails.
 */
#include "Cenotaph.h"

FUNC ULONG HashString( PVOID String, SIZE_T Length ) {
    ULONG  Hash = 0;
    PUCHAR Ptr  = NULL;
    UCHAR  Char = 0;

    if ( ! String )
        return 0;

    Hash = H_MAGIC_KEY;
    Ptr  = (PUCHAR) String;

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( U_PTR( Ptr ) - U_PTR( String ) ) >= Length ) break;
            if ( ! *Ptr ) ++Ptr;
        }

        if ( Char >= 'a' )
            Char -= 0x20;

        Hash ^= Char;
        Hash *= H_MAGIC_PRIME;

        ++Ptr;
    } while ( 1 );

    return Hash;
}