/*
 * tests/test_bof.c — minimal BOF for end-to-end loader validation.
 *
 * Build: x86_64-w64-mingw32-gcc -c -o tests/test_bof.o tests/test_bof.c
 */

void BeaconPrintf(int type, const char* fmt, ...);

void go(char* args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(0, "[+] test_bof: go() executed\n");
}
