;; NaX src_loader - entry stubs
;;
;; Sections:
;;   .text$A  - Start / StRipStart
;;   .text$E  - StRipEnd   (MUST be last section)

[BITS 64]

DEFAULT REL

EXTERN PreMain

GLOBAL Start
GLOBAL StRipStart
GLOBAL StRipEnd

;; ========= [ .text$A - entry stubs ] =========
[SECTION .text$A]

    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  PreMain
        mov   rsp, rsi
        pop   rsi
        ret

    StRipStart:
        lea   rax, [Start]
        ret

;; ========= [ .text$E - end marker ] =========
[SECTION .text$E]

    StRipEnd:
        lea   rax, [.loader_end]    ; 7 bytes
        ret                          ; 1 byte
        nop                          ; 8 bytes of padding to fill 16-byte section
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    .loader_end:
