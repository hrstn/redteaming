/* beacon/Linker.ld
 * Pack code and data into .text, unwind metadata into .pdata/.xdata.
 *
 * .text ordering (CRITICAL - do NOT reorder):
 *   .text$A  - ASM entry stubs (Start, StartPtr)
 *   .text$B* - FUNC-annotated C code + ASM helpers (___chkstk_ms)
 *   .rdata*  - compile-time string literals and GCC ident strings
 *   .data*   - GCC-generated WCHAR initializer copies for local arrays
 *   .text$*  - orphan functions: static helpers, GCC .constprop clones,
 *              and import library stubs that don't carry the FUNC macro.
 *              EXCLUDE_FILE keeps Entry.obj's .text$C out of this catch-all.
 *   .text    - bare .text sections (import thunks from -lwinhttp etc.)
 *   .text$C  - EndPtr marker (MUST be last - stomp tag lives right after it)
 *
 * .pdata / .xdata:
 *   Extracted separately for module-stomp unwind fixup.
 *   .pdata$func → RUNTIME_FUNCTION entries (12 bytes each, sorted by addr)
 *   .xdata$func → UNWIND_INFO + UNWIND_CODE data
 */
SECTIONS
{
    .text :
    {
        *(.text$A)
        *(.text$B*)
        *(.rdata*)
        *(.data*)
        *(EXCLUDE_FILE(*Entry.obj) .text$*)
        *(.text)
        *(.text$C)
    }
    .pdata ALIGN(4) :
    {
        *(.pdata*)
    }
    .xdata ALIGN(4) :
    {
        *(.xdata*)
    }
}
