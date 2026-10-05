#ifndef NAX_ADV_CONSTEXPR_H
#define NAX_ADV_CONSTEXPR_H

#include <windows.h>

#define CONSTEXPR   constexpr
#define HASH_STR(x) ExprHashStringA((x))

CONSTEXPR ULONG ExprHashStringA( PCHAR String ) {
    ULONG Hash = 0x811c9dc5;
    CHAR  Char = 0;

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' ) Char -= 0x20;
        Hash ^= (UCHAR)Char;
        Hash *= 0x01000193;
    }

    return Hash;
}

#endif // NAX_ADV_CONSTEXPR_H
