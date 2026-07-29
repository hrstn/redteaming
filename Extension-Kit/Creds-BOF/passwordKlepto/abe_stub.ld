/* abe_stub.ld — produce a flat .text blob with entry() at offset 0.
   Used with: ld -T abe_stub.ld --oformat binary -o abe_stub.bin abe_stub.o
   KEEP(*(.text.entry)) guarantees the section containing entry() is placed
   first, so the CreateRemoteThread start address == remoteBase + 0. */
SECTIONS {
  . = 0;
  .text : {
    KEEP(*(.text.entry))
    *(.text*)
  }
  /* anything the compiler might still emit is dropped; if it carried real
     content the .o audit (readelf -r / nm -u) would have flagged it already */
  /DISCARD/ : {
    *(.rdata*) *(.data*) *(.pdata*) *(.xdata*) *(.bss*)
    *(.comment*) *(.note*) *(.eh_frame*) *(.eh_frame_hdr*)
  }
}