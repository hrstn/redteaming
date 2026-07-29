CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
LD64 = x86_64-w64-mingw32-ld
LD86 = i686-w64-mingw32-ld
OC64 = x86_64-w64-mingw32-objcopy
OC86 = i686-w64-mingw32-objcopy
CFLAGS = -I ../_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -s -DBOF -c
# ABE hollow PIC stub: pure-.text, no imports, no absolute relocations.
# -O0 keeps the stack-built constant arrays as immediate stores (no .rdata);
# -fno-tree-loop-distribute-patterns keeps manual copy/cmp loops from turning
# into memset/memcmp/strcmp libcalls (there is no libc in the stub at all).
# mingw ld refuses --oformat binary, so link to a tiny PE then objcopy -O binary.
STUBCFLAGS = -O0 -fno-stack-protector -nostdlib -fno-asynchronous-unwind-tables -fno-ident -fno-exceptions -fno-tree-loop-distribute-patterns -c

all: bof

bof: clean
	# 64-bit builds
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	# ABE hollow PIC stub -> generated C byte-array header (must run before
	# passwordKlepto compiles, which #include "abe_stub_bin.<arch>.h").
	@($(CC64) $(STUBCFLAGS) passwordKlepto/abe_stub.c -o _bin/abe_stub.x64.o && $(LD64) --image-base=0 -T passwordKlepto/abe_stub.ld -o _bin/abe_stub.x64.exe _bin/abe_stub.x64.o && $(OC64) -O binary _bin/abe_stub.x64.exe _bin/abe_stub.x64.bin && xxd -i -n abe_stub_bin _bin/abe_stub.x64.bin > passwordKlepto/abe_stub_bin.x64.h) && echo '[+] abe_stub (x64)' || echo '[!] abe_stub (x64)'
	@($(CC86) $(STUBCFLAGS) passwordKlepto/abe_stub.c -o _bin/abe_stub.x32.o && $(LD86) --image-base=0 -T passwordKlepto/abe_stub.ld -o _bin/abe_stub.x32.exe _bin/abe_stub.x32.o && $(OC86) -O binary _bin/abe_stub.x32.exe _bin/abe_stub.x32.bin && xxd -i -n abe_stub_bin _bin/abe_stub.x32.bin > passwordKlepto/abe_stub_bin.x32.h) && echo '[+] abe_stub (x32)' || echo '[!] abe_stub (x32)'
	@($(CC64) $(CFLAGS) askcreds/askcreds.c -o _bin/askcreds.x64.o   && $(STRIP64) _bin/askcreds.x64.o) && echo '[+] askcreds' || echo '[!] askcreds'
	@($(CC64) $(CFLAGS) cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x64.o && $(STRIP64) _bin/cookie-monster-bof.x64.o)  && echo '[+] cookie-monster-bof' || echo '[!] cookie-monster-bof'
	@($(CC64) $(CFLAGS) passwordKlepto/passwordKlepto.c -o _bin/passwordKlepto.x64.o && $(STRIP64) _bin/passwordKlepto.x64.o)  && echo '[+] passwordKlepto' || echo '[!] passwordKlepto'
	@($(CC64) $(CFLAGS) browserHistory/browserHistory.c -o _bin/browserHistory.x64.o && $(STRIP64) _bin/browserHistory.x64.o)  && echo '[+] browserHistory' || echo '[!] browserHistory'
	@($(CC64) $(CFLAGS) hashdump/hashdump.c -o _bin/hashdump.x64.o && $(STRIP64) _bin/hashdump.x64.o)  && echo '[+] hashdump' || echo '[!] hashdump'
	@($(CC64) $(CFLAGS) get-netntlm/get-netntlm.c -o _bin/get-netntlm.x64.o && $(STRIP64) _bin/get-netntlm.x64.o)  && echo '[+] get-netntlm' || echo '[!] get-netntlm'
	@($(CC64) $(CFLAGS) -masm=intel UnderlayCopy/entry.c -o _bin/underlaycopy.x64.o && $(STRIP64) _bin/underlaycopy.x64.o)  && echo '[+] underlaycopy' || echo '[!] underlaycopy'
	@($(CC64) $(CFLAGS) lsadump/secrets.c -o _bin/lsadump_secrets.x64.o && $(STRIP64) _bin/lsadump_secrets.x64.o) && echo '[+] lsadump-secrets' || echo '[!] lsadump-secrets'
	@($(CC64) $(CFLAGS) lsadump/sam.c -o _bin/lsadump_sam.x64.o && $(STRIP64) _bin/lsadump_sam.x64.o) && echo '[+] lsadump-sam' || echo '[!] lsadump-sam'
	@($(CC64) $(CFLAGS) lsadump/cache.c -o _bin/lsadump_cache.x64.o && $(STRIP64) _bin/lsadump_cache.x64.o) && echo '[+] lsadump-cache' || echo '[!] lsadump-cache'

	# 32-bit builds
	@#($(CC86) $(CFLAGS) askcreds/askcreds.c -o _bin/askcreds.x32.o   && $(STRIP86) _bin/askcreds.x32.o) && echo '[+] askcreds (x32)' || echo '[!] askcreds (x32)'
	@($(CC86) $(CFLAGS) cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x32.o && $(STRIP86) _bin/cookie-monster-bof.x32.o)  && echo '[+] cookie-monster-bof (x32)' || echo '[!] cookie-monster-bof (x32)'
	@($(CC86) $(CFLAGS) passwordKlepto/passwordKlepto.c -o _bin/passwordKlepto.x32.o && $(STRIP86) _bin/passwordKlepto.x32.o)  && echo '[+] passwordKlepto (x32)' || echo '[!] passwordKlepto (x32)'
	@($(CC86) $(CFLAGS) browserHistory/browserHistory.c -o _bin/browserHistory.x32.o && $(STRIP86) _bin/browserHistory.x32.o)  && echo '[+] browserHistory (x32)' || echo '[!] browserHistory (x32)'
	@($(CC86) $(CFLAGS) hashdump/hashdump.c -o _bin/hashdump.x32.o && $(STRIP86) _bin/hashdump.x32.o)  && echo '[+] hashdump (x32)' || echo '[!] hashdump (x32)'
	@($(CC86) $(CFLAGS) get-netntlm/get-netntlm.c -o _bin/get-netntlm.x32.o && $(STRIP86) _bin/get-netntlm.x32.o)  && echo '[+] get-netntlm (x32)' || echo '[!] get-netntlm (x32)'
	@($(CC86) $(CFLAGS) UnderlayCopy/entry.c -o _bin/underlaycopy.x32.o && $(STRIP86) _bin/underlaycopy.x32.o)  && echo '[+] underlaycopy (x32)' || echo '[!] underlaycopy (x32)'
	@#($(CC86) $(CFLAGS) lsadump/secrets.c -o _bin/lsadump_secrets.x32.o && $(STRIP86) _bin/lsadump_secrets.x32.o) && echo '[+] lsadump-secrets' || echo '[!] lsadump-secrets'
	@#($(CC86) $(CFLAGS) lsadump/sam.c -o _bin/lsadump_sam.x32.o && $(STRIP86) _bin/lsadump_sam.x32.o) && echo '[+] lsadump-sam' || echo '[!] lsadump-sam'
	@#($(CC86) $(CFLAGS) lsadump/cache.c -o _bin/lsadump_cache.x32.o && $(STRIP86) _bin/lsadump_cache.x32.o) && echo '[+] lsadump-cache' || echo '[!] lsadump-cache'

	@$(MAKE) --no-print-directory -C nanodump
	@cp nanodump/dist/*.o _bin/

clean:
	@(rm -rf _bin)
