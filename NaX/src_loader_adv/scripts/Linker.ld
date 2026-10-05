/* NaX Advanced Loader linker script */

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
