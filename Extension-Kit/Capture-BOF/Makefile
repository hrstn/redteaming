CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) clipmon/clipmon.c -o _bin/clipmon.x64.o && $(STRIP64) _bin/clipmon.x64.o) && echo '[+] clipmon' || echo '[!] clipmon'
	@($(CC64) $(CFLAGS) keylog/keylog.c   -o _bin/keylog.x64.o && $(STRIP64) _bin/keylog.x64.o) && echo '[+] keylog' || echo '[!] keylog'
	@($(CC86) $(CFLAGS) clipmon/clipmon.c -o _bin/clipmon.x86.o && $(STRIP86) _bin/clipmon.x86.o) && echo '[+] clipmon (x86)' || echo '[!] clipmon (x86)'
	@($(CC86) $(CFLAGS) keylog/keylog.c   -o _bin/keylog.x86.o && $(STRIP86) _bin/keylog.x86.o) && echo '[+] keylog (x86)' || echo '[!] keylog (x86)'

clean:
	@(rm -rf _bin)