CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = x86_64-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -masm=intel -w -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'
	@($(CC64) $(CFLAGS) wmisub/wmi_sub.c            -o _bin/wmisub.x64.o && $(STRIP64) _bin/wmisub.x64.o) && echo '[+] wmisub' || echo '[!] wmisub'
	@($(CC64) $(CFLAGS) wmiclear/wmi_clear.c        -o _bin/wmiclear.x64.o && $(STRIP64) _bin/wmiclear.x64.o) && echo '[+] wmiclear' || echo '[!] wmiclear'
	@($(CC64) $(CFLAGS) taskcreate/task_create.c    -o _bin/taskcreate.x64.o && $(STRIP64) _bin/taskcreate.x64.o) && echo '[+] taskcreate' || echo '[!] taskcreate'
	@($(CC64) $(CFLAGS) taskdelete/task_delete.c    -o _bin/taskdelete.x64.o && $(STRIP64) _bin/taskdelete.x64.o) && echo '[+] taskdelete' || echo '[!] taskdelete'
	@($(CC64) $(CFLAGS) runkey/runkey.c             -o _bin/runkey.x64.o && $(STRIP64) _bin/runkey.x64.o) && echo '[+] runkey' || echo '[!] runkey'
	@($(CC64) $(CFLAGS) comhijack/comhijack.c       -o _bin/comhijack.x64.o && $(STRIP64) _bin/comhijack.x64.o) && echo '[+] comhijack' || echo '[!] comhijack'
	@($(CC64) $(CFLAGS) inventory/persist_inventory.c -o _bin/persist_inventory.x64.o && $(STRIP64) _bin/persist_inventory.x64.o) && echo '[+] persist_inventory' || echo '[!] persist_inventory'
	@($(CC86) $(CFLAGS) wmisub/wmi_sub.c            -o _bin/wmisub.x86.o && $(STRIP86) _bin/wmisub.x86.o) && echo '[+] wmisub (x86)' || echo '[!] wmisub (x86)'
	@($(CC86) $(CFLAGS) wmiclear/wmi_clear.c        -o _bin/wmiclear.x86.o && $(STRIP86) _bin/wmiclear.x86.o) && echo '[+] wmiclear (x86)' || echo '[!] wmiclear (x86)'
	@($(CC86) $(CFLAGS) taskcreate/task_create.c    -o _bin/taskcreate.x86.o && $(STRIP86) _bin/taskcreate.x86.o) && echo '[+] taskcreate (x86)' || echo '[!] taskcreate (x86)'
	@($(CC86) $(CFLAGS) taskdelete/task_delete.c    -o _bin/taskdelete.x86.o && $(STRIP86) _bin/taskdelete.x86.o) && echo '[+] taskdelete (x86)' || echo '[!] taskdelete (x86)'
	@($(CC86) $(CFLAGS) runkey/runkey.c             -o _bin/runkey.x86.o && $(STRIP86) _bin/runkey.x86.o) && echo '[+] runkey (x86)' || echo '[!] runkey (x86)'
	@($(CC86) $(CFLAGS) comhijack/comhijack.c       -o _bin/comhijack.x86.o && $(STRIP86) _bin/comhijack.x86.o) && echo '[+] comhijack (x86)' || echo '[!] comhijack (x86)'
	@($(CC86) $(CFLAGS) inventory/persist_inventory.c -o _bin/persist_inventory.x86.o && $(STRIP86) _bin/persist_inventory.x86.o) && echo '[+] persist_inventory (x86)' || echo '[!] persist_inventory (x86)'

clean:
	@(rm -rf _bin)