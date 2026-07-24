# sleepmask/Makefile - compile sleepmask as BOF (.o COFF object)
#
# Output: dist/sleepmask.x64.o  (loaded by beacon's COFF loader at runtime)

CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -O0 -w -Iinclude -D__USE_MINGW_ANSI_STDIO=0

DIST    := dist
OUT     := $(DIST)/sleepmask.x64.o
VARIANT := $(DIST)/.variant

.PHONY: all debug clean

all: _ensure_release $(OUT)

debug: _ensure_debug $(OUT)
	@echo "[*] Sleepmask: DEBUG build"

_ensure_release: | $(DIST)
	@echo "release" > $(VARIANT).new
	@if ! cmp -s $(VARIANT) $(VARIANT).new 2>/dev/null; then mv $(VARIANT).new $(VARIANT); rm -f $(OUT); else rm -f $(VARIANT).new; fi

_ensure_debug: | $(DIST)
	@echo "debug" > $(VARIANT).new
	@if ! cmp -s $(VARIANT) $(VARIANT).new 2>/dev/null; then mv $(VARIANT).new $(VARIANT); rm -f $(OUT); else rm -f $(VARIANT).new; fi
	$(eval CFLAGS += -DDEBUG)

$(DIST):
	mkdir -p $(DIST)

$(OUT): src/main.c include/Imports.h include/Gate.h | $(DIST)
	@echo "  SM_BOF  $@"
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf $(DIST)
