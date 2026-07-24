; beacon/asm/Entry.x64.asm
; ASM entry point.  Aligns stack, calls NaxMain, provides StartPtr/EndPtr
; so the loader can calculate the beacon's address and size.
; Follows the Kharon pattern (StartPtr/EndPtr) with DEFAULT REL from Stardust.

[BITS 64]
DEFAULT REL

EXTERN NaxMain

GLOBAL StartPtr
GLOBAL EndPtr
GLOBAL ___chkstk_ms

[SECTION .text$A]
    ; ---- entry ----
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  NaxMain
        mov   rsp, rsi
        pop   rsi
        ret

    ; StartPtr() returns the address of Start via call/ret trick.
    ;   Start body:
    ;     push(1) + mov(3) + and(4) + sub(4) + call(5) + mov(3) + pop(1) + ret(1) = 22
    ;   call RetStartPtr:  5 bytes
    ;   ret:               1 byte  <- [rsp] points here
    ;   Total from Start to [rsp]: 22 + 5 = 27 = 0x1b
    StartPtr:
        call  RetStartPtr
        ret
    RetStartPtr:
        mov   rax, [rsp]
        sub   rax, 0x1b
        ret

; ========= [ stack probe - ___chkstk_ms ] =========
; GCC emits  mov rax, <frame_size> / call ___chkstk_ms / sub rsp, rax
; for any function whose frame exceeds 4 KB.  Without the probe, sub rsp
; jumps over guard pages and faults on the first stack write beyond them.
; RAX = bytes to probe (preserved on return).  RCX clobbered internally.
[SECTION .text$B]

___chkstk_ms:
    push  rcx
    push  rax
    cmp   rax, 0x1000
    lea   rcx, [rsp + 0x18]         ; rcx = caller RSP before CALL
    jb    .chkstk_done
.chkstk_loop:
    sub   rcx, 0x1000
    or    dword [rcx], 0            ; touch page - triggers guard-page commit
    sub   rax, 0x1000
    cmp   rax, 0x1000
    ja    .chkstk_loop
.chkstk_done:
    sub   rcx, rax
    or    dword [rcx], 0
    pop   rax
    pop   rcx
    ret

[SECTION .text$C]
    ; EndPtr() returns the address past itself - i.e., the end of the beacon blob.
    ; Used by the loader to calculate beacon size: EndPtr() - StartPtr().
    ; After `call RetEndPtr`, [rsp] = address of the `ret` in EndPtr (section offset 0x05).
    ; Section layout:
    ;   0x00  call RetEndPtr  (5 bytes)
    ;   0x05  ret             (1 byte)  <- [rsp] lands here
    ;   0x06  mov rax,[rsp]   (4 bytes)
    ;   0x0a  add rax, 0x0a   (4 bytes)
    ;   0x0e  ret             (1 byte)
    ;   0x0f  <- one-past-end
    ; [rsp] = 0x05; 0x05 + 0x0a = 0x0f = one-past-end of section.
    EndPtr:
        call  RetEndPtr
        ret
    RetEndPtr:
        mov   rax, [rsp]
        add   rax, 0x0a
        ret
