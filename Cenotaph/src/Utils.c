/*
 * FNV1a-32 case-insensitive hash.
 *
 * This must be byte-identical to the NaX loader's HashString().
 * The non-zero Length path skips embedded nulls (needed because
 * UNICODE_STRING.Buffer is wide, so every second byte is 0).
 */
#include "Cenotaph.h"

extern "C" ULONG CenHashString( PVOID String, SIZE_T Length ) {
    ULONG  Hash = H_MAGIC_KEY;
    PUCHAR Ptr  = (PUCHAR)String;
    UCHAR  Char = 0;

    if ( ! String )
        return 0;

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr )
                break;
        } else {
            if ( (SIZE_T)( Ptr - (PUCHAR)String ) >= Length )
                break;
            if ( ! *Ptr )
                Ptr++;
        }

        if ( Char >= 'a' )
            Char -= 0x20;

        Hash ^= Char;
        Hash *= H_MAGIC_PRIME;

        Ptr++;
    } while ( TRUE );

    return Hash;
}
