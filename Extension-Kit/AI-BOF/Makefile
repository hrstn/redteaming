# AI-BOF — OSAI AdaptixC2 Beacon Object Files
# Builds Windows COFF (.o) for x64 + x86, matching Extension-Kit conventions.
# Sources in src/, include "aibof.h" (local) + beacon.h/bofdefs.h (../_include).
#
#   make         -> _bin/*.x64.o + *.x86.o
#   make x64     -> 64-bit only
#   make clean

CC64   = x86_64-w64-mingw32-gcc
CC86   = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip
STRIP86 = i686-w64-mingw32-strip
# -fno-tree-loop-distribute-patterns: stop gcc turning our manual zero/copy
#   loops into memset/memcpy LIBRARY calls (bare -> unresolved by the loader).
CFLAGS = -I ../_include -I src -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -fno-tree-loop-distribute-patterns -DBOF -s -c

# mininflate.c is #included by gitMine.c — NOT built standalone.
BOFS = aiHunter credsMem credsLaunch envScraper aiSvcProbe shareWalk poisonStage \
       configDump logTail kubeHunter tokenizerSwap picklePlant gitMine \
       vectorExport sessionBrute credVault

OBJ64 = $(patsubst %,_bin/%.x64.o,$(BOFS))
OBJ86 = $(patsubst %,_bin/%.x86.o,$(BOFS))

all: x64 x86

x64: $(OBJ64)
x86: $(OBJ86)

_bin/%.x64.o: src/%.c
	@mkdir -p _bin
	$(CC64) $(CFLAGS) $< -o $@
	$(STRIP64) --strip-unneeded $@

_bin/%.x86.o: src/%.c
	@mkdir -p _bin
	$(CC86) $(CFLAGS) $< -o $@
	$(STRIP86) --strip-unneeded $@

clean:
	rm -rf _bin

.PHONY: all x64 x86 clean