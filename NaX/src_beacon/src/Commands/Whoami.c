/* beacon/src/Commands/Whoami.c
 * CMD_WHOAMI (0x10) - return current username as UTF-8. */

#include "Nax.h"

FUNC INT NaxCmdWhoami( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    WCHAR wbuf[256];
    DWORD wlen = 256;

    if ( ! Nax->Advapi32.GetUserNameW( wbuf, &wlen ) )
        return NAX_ERR_INVAL;

    INT n = Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, wbuf, -1,
                                               (PCHAR)out, (INT)*out_len,
                                               NULL, NULL );
    if ( n <= 0 ) return NAX_ERR_NOMEM;
    *out_len = (UINT32)( n - 1 );
    return NAX_OK;
}
