;; NaX Advanced Loader - entry stubs
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

[SECTION .text$E]

    StRipEnd:
        lea   rax, [.loader_end]
        ret
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    .loader_end:
