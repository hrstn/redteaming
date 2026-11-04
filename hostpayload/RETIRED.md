# RETIRED — superseded by hostpayload_v2 (do not build, do not ship)

> Decision: OPSEC audit 2026-11-04 (internal notes, not committed) — verdict **CRITICAL** (score 3/10).
> Successor: `../hostpayload_v2/` — native droppers (embed/fetch), ChaCha20+HMAC,
> no RWX, no PowerShell execution path, build/validate gates.

Every generated loader in this directory carries the same tells
(`../hostpayload_v2/README.md:14-23` documents the kill list):

- Signatured `amsiInitFailed` reflection bypass in both template
  (`modules/generators/ps1.py:138-145`) and Chimera-flavored form
  (`modules/obfuscation.py:187-211`).
- `VirtualAlloc(MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` + `CreateThread`
  from the PS/C# host (`modules/generators/ps1.py:182-185`) — RWX + unbacked
  thread start.
- `pinject` = OpenProcess + VirtualAllocEx + WriteProcessMemory +
  CreateRemoteThread (`modules/generators/cs.py:42-45`) — Sysmon 8 / ETW-TI.
- Toy ciphers with plaintext-key arrays; fake Microsoft doc-comment headers
  (`modules/obfuscation.py:16-38`).

Do not regenerate payloads from this tree. Do not delete the directory without
regard for the Donut-conversion snippets (`payloader.py:70-85`), which the fix
plan may reuse for a v2 optional pass — otherwise remove after the fix plan's
P1 items land.