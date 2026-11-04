# RETIRED — superseded by src_loader_adv (Stardust)

> Decision: OPSEC audit 2026-11-04 (internal notes, not committed) — superseded, see below.
> Successor: `../src_loader_adv/`.

This basic loader lacks the countermeasures that make the deployable chain
clean against a top-tier EDR:

- No clean (fresh-mapped) ntdll — syscalls are taken from the possibly-hooked
  in-process ntdll (`src/Syscall.c`, `src/Ldr.c`), unlike Stardust's
  `NaxMapCleanNtdll` (`src_loader_adv/src/PreMain.c:12-35`).
- No module-stomp placement mode (`src_loader_adv/src/Stomp.c:68+`) — virtual
  RW→RX only.
- No staged-copy wipe, no CFG whitelist, no anti-analysis gate.

Keeping both loaders doubles the shared FNV1a/PEB-chain signature surface for
zero capability gain. Do not build; if the advanced loader is ever unavailable
for a minimal build, fix this tree first rather than shipping it (P3 item 2 in
the fix plan covers the resolver replacement that would benefit both).