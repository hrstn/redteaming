#define MAX_FILE_SIZE 2048
#define MAX_PATH_SIZE 512

/* NaxWriteWin32Err - write TEB->LastErrorValue as 4-byte LE into the result
 * buffer so the server can display a meaningful Win32 error name.
 * Must be called BEFORE any subsequent API that could overwrite LastError.  */
#define NaxWriteWin32Err( out_ptr, out_len_ptr ) do {       \
    DWORD  _e = NaxCurrentTeb()->LastErrorValue;            \
    PBYTE  _p = (PBYTE)(out_ptr);                           \
    _p[0] = (BYTE)(  _e        & 0xFF );                    \
    _p[1] = (BYTE)( (_e >>  8) & 0xFF );                    \
    _p[2] = (BYTE)( (_e >> 16) & 0xFF );                    \
    _p[3] = (BYTE)( (_e >> 24) & 0xFF );                    \
    *(out_len_ptr) = 4;                                      \
} while(0)
