"""
Multi-layer encryption chain orchestrator.

Chain spec format (--chain argument):
  xor:KEY=0xAA,aes256:KEY=secret;IV=myiv16bytes12345,rot:N=13

  - Stages separated by commas.
  - Parameters within a stage separated by semicolons.
  - KEY/IV values use the same format as parse_key() in crypto.py.

Encryption is applied left-to-right.
Decryption code must run right-to-left.
"""

import os
from . import crypto
from .utils import generate_key


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_chain_spec(chain_str: str) -> list[dict]:
    """Return a list of stage dicts: {'algo': str, 'params': dict}."""
    stages = []
    for part in chain_str.split(','):
        part = part.strip()
        if not part:
            continue
        if ':' in part:
            algo, params_str = part.split(':', 1)
        else:
            algo, params_str = part, ''

        params: dict[str, str] = {}
        for p in params_str.split(';'):
            p = p.strip()
            if '=' in p:
                k, v = p.split('=', 1)
                params[k.strip().upper()] = v.strip()

        stages.append({'algo': algo.strip().lower(), 'params': params})
    return stages


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def apply_chain(data: bytes, stages: list[dict]) -> tuple[bytes, list[dict]]:
    """
    Encrypt data through all stages in order.

    Returns:
      encrypted_data  – final ciphertext
      metadata        – list of per-stage dicts with resolved keys/IVs/params
                        (same order as stages, so index 0 == first applied)
    """
    result = data
    metadata: list[dict] = []

    for stage in stages:
        algo = stage['algo']
        params = stage.get('params', {})

        if algo == 'xor':
            key_str = params.get('KEY')
            key = crypto.parse_key(key_str) if key_str else generate_key(16)
            result = crypto.xor_encrypt(result, key)
            metadata.append({'algo': 'xor', 'key': key})

        elif algo in ('aes256', 'aes'):
            key_str = params.get('KEY')
            iv_str  = params.get('IV')
            key = crypto.parse_key(key_str) if key_str else generate_key(32)
            iv  = crypto.parse_key(iv_str)  if iv_str  else os.urandom(16)
            result = crypto.aes256_cbc_encrypt(result, key, iv)
            metadata.append({'algo': 'aes256',
                             'key': crypto._derive_key(key, 32),
                             'iv': crypto._pad_iv(iv)})

        elif algo == 'rc4':
            key_str = params.get('KEY')
            key = crypto.parse_key(key_str) if key_str else generate_key(16)
            result = crypto.rc4_encrypt(result, key)
            metadata.append({'algo': 'rc4', 'key': key})

        elif algo == 'rot':
            n = int(params.get('N', 13))
            result = crypto.rot_encrypt(result, n)
            metadata.append({'algo': 'rot', 'n': n})

        else:
            raise ValueError(f"Unknown algorithm in chain: '{algo}'. "
                             "Valid: xor, aes256, rc4, rot")

    return result, metadata


# ---------------------------------------------------------------------------
# Single-algorithm convenience builder
# ---------------------------------------------------------------------------

def build_single_stage(algo: str, key: bytes | None = None,
                        iv: bytes | None = None, rot_n: int = 13) -> dict:
    """Build a stages list containing one algorithm, ready for apply_chain()."""
    algo = algo.lower()
    params: dict[str, str] = {}

    if key:
        params['KEY'] = key.hex() if len(key) > 1 else f'0x{key[0]:02x}'
    if iv and algo in ('aes256', 'aes'):
        params['IV'] = iv.hex()
    if algo == 'rot':
        params['N'] = str(rot_n)

    return {'algo': algo, 'params': params}


# ---------------------------------------------------------------------------
# Decryption code generators  (each lang returns a string of source code)
# ---------------------------------------------------------------------------

def decryption_stubs_ps1(metadata: list[dict]) -> tuple[list[str], str]:
    """
    Generate PowerShell decryption stubs for the chain.

    Returns:
      helper_functions  – list of function definition strings
      exec_code         – sequential call code that decrypts $encrypted → $buf
    """
    helpers: list[str] = []
    calls: list[str] = []

    # Stubs are applied in reverse
    for stage in reversed(metadata):
        algo = stage['algo']

        if algo == 'xor':
            fn = _random_fn()
            key_arr = _ps1_key_arr(stage['key'])
            helpers.append(_PS1_XOR_FN.format(fn=fn))
            calls.append(f'$buf = {fn} $buf {key_arr}')

        elif algo == 'rc4':
            fn = _random_fn()
            key_arr = _ps1_key_arr(stage['key'])
            helpers.append(_PS1_RC4_FN.format(fn=fn))
            calls.append(f'$buf = {fn} $buf {key_arr}')

        elif algo == 'aes256':
            fn = _random_fn()
            key_arr = _ps1_key_arr(stage['key'])
            iv_arr  = _ps1_key_arr(stage['iv'])
            helpers.append(_PS1_AES_FN.format(fn=fn))
            calls.append(f'$buf = {fn} $buf {key_arr} {iv_arr}')

        elif algo == 'rot':
            n = (256 - stage['n']) % 256   # inverse rotation
            fn = _random_fn()
            helpers.append(_PS1_ROT_FN.format(fn=fn))
            calls.append(f'$buf = {fn} $buf {n}')

    exec_code = '[Byte[]] $buf = $encrypted\n' + '\n'.join(calls)
    return helpers, exec_code


def decryption_stubs_cs(metadata: list[dict]) -> tuple[str, str]:
    """
    Generate C# decryption method definitions and call sequence.

    Returns:
      helper_methods  – static method definitions (string)
      exec_code       – sequential call code decrypting byte[] buf
    """
    methods_parts: list[str] = []
    calls: list[str] = []

    for stage in reversed(metadata):
        algo = stage['algo']

        if algo == 'xor':
            fn = _random_fn()
            key_cs = _cs_key_arr(stage['key'])
            methods_parts.append(_CS_XOR_FN.format(fn=fn))
            calls.append(f'buf = {fn}(buf, new byte[] {key_cs});')

        elif algo == 'rc4':
            fn = _random_fn()
            key_cs = _cs_key_arr(stage['key'])
            methods_parts.append(_CS_RC4_FN.format(fn=fn))
            calls.append(f'buf = {fn}(buf, new byte[] {key_cs});')

        elif algo == 'aes256':
            fn = _random_fn()
            key_cs = _cs_key_arr(stage['key'])
            iv_cs  = _cs_key_arr(stage['iv'])
            methods_parts.append(_CS_AES_FN.format(fn=fn))
            calls.append(f'buf = {fn}(buf, new byte[] {key_cs}, new byte[] {iv_cs});')

        elif algo == 'rot':
            n = (256 - stage['n']) % 256
            fn = _random_fn()
            methods_parts.append(_CS_ROT_FN.format(fn=fn))
            calls.append(f'buf = {fn}(buf, {n});')

    return '\n'.join(methods_parts), '\n        '.join(calls)


def decryption_stubs_vba(metadata: list[dict]) -> tuple[str, str]:
    """Return (helper_functions_str, call_sequence_str) for VBA."""
    helpers: list[str] = []
    calls: list[str] = []

    for stage in reversed(metadata):
        algo = stage['algo']

        if algo == 'xor':
            key = stage['key']
            if len(key) == 1:
                fn = _random_fn()
                helpers.append(_VBA_XOR1_FN.format(fn=fn))
                calls.append(f'    buf = {fn}(buf, {key[0]})')
            else:
                fn = _random_fn()
                key_vba = ', '.join(str(b) for b in key)
                helpers.append(_VBA_XORN_FN.format(fn=fn))
                calls.append(f'    Dim k_{fn}() As Byte\n'
                              f'    k_{fn} = Array({key_vba})\n'
                              f'    buf = {fn}(buf, k_{fn})')

        elif algo == 'rc4':
            fn = _random_fn()
            key_vba = ', '.join(str(b) for b in stage['key'])
            helpers.append(_VBA_RC4_FN.format(fn=fn))
            calls.append(f'    Dim k_{fn}() As Byte\n'
                         f'    k_{fn} = Array({key_vba})\n'
                         f'    buf = {fn}(buf, k_{fn})')

        elif algo == 'rot':
            n = (256 - stage['n']) % 256
            fn = _random_fn()
            helpers.append(_VBA_ROT_FN.format(fn=fn))
            calls.append(f'    buf = {fn}(buf, {n})')

        elif algo == 'aes256':
            raise ValueError("AES-256 is not supported for VBA output format. "
                             "Use XOR or RC4 for VBA macros.")

    return '\n\n'.join(helpers), '\n'.join(calls)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

import random
import string as _string

def _random_fn(length: int = 12) -> str:
    return ''.join(random.choice(_string.ascii_letters) for _ in range(length))


def _ps1_key_arr(key: bytes) -> str:
    return '([Byte[]] @(' + ','.join(f'0x{b:02X}' for b in key) + '))'


def _cs_key_arr(key: bytes) -> str:
    return '{ ' + ', '.join(f'0x{b:02x}' for b in key) + ' }'


# ---------------------------------------------------------------------------
# PowerShell stub templates
# ---------------------------------------------------------------------------

_PS1_XOR_FN = """\
function {fn}([Byte[]]$d,[Byte[]]$k){{
    $r=New-Object Byte[] $d.Length
    for($i=0;$i-lt$d.Length;$i++){{$r[$i]=$d[$i]-bxor$k[$i%$k.Length]}}
    return $r
}}"""

_PS1_RC4_FN = """\
function {fn}([Byte[]]$d,[Byte[]]$k){{
    $S=0..255;$j=0
    for($i=0;$i-lt 256;$i++){{$j=($j+$S[$i]+$k[$i%$k.Length])%256;$t=$S[$i];$S[$i]=$S[$j];$S[$j]=$t}}
    $r=New-Object Byte[] $d.Length;$i=0;$j=0
    for($n=0;$n-lt$d.Length;$n++){{$i=($i+1)%256;$j=($j+$S[$i])%256;$t=$S[$i];$S[$i]=$S[$j];$S[$j]=$t;$r[$n]=$d[$n]-bxor$S[($S[$i]+$S[$j])%256]}}
    return $r
}}"""

_PS1_AES_FN = """\
function {fn}([Byte[]]$d,[Byte[]]$k,[Byte[]]$iv){{
    $a=[System.Security.Cryptography.Aes]::Create()
    $a.KeySize=256;$a.Mode='CBC';$a.Padding='PKCS7';$a.Key=$k;$a.IV=$iv
    $dc=$a.CreateDecryptor()
    $ms=New-Object System.IO.MemoryStream(,$d)
    $cs=New-Object System.Security.Cryptography.CryptoStream($ms,$dc,[System.Security.Cryptography.CryptoStreamMode]::Read)
    $out=New-Object System.IO.MemoryStream
    $cs.CopyTo($out);$cs.Close()
    return $out.ToArray()
}}"""

_PS1_ROT_FN = """\
function {fn}([Byte[]]$d,[int]$n){{
    $r=New-Object Byte[] $d.Length
    for($i=0;$i-lt$d.Length;$i++){{$r[$i]=[Byte](($d[$i]+$n)%256)}}
    return $r
}}"""


# ---------------------------------------------------------------------------
# C# stub templates
# ---------------------------------------------------------------------------

_CS_XOR_FN = """\
    static byte[] {fn}(byte[] data, byte[] key) {{
        byte[] r = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key[i % key.Length]);
        return r;
    }}"""

_CS_RC4_FN = """\
    static byte[] {fn}(byte[] data, byte[] key) {{
        int[] S = new int[256]; int j = 0;
        for (int i = 0; i < 256; i++) S[i] = i;
        for (int i = 0; i < 256; i++) {{ j = (j + S[i] + key[i % key.Length]) % 256; int t = S[i]; S[i] = S[j]; S[j] = t; }}
        byte[] r = new byte[data.Length]; int x = 0; j = 0;
        for (int n = 0; n < data.Length; n++) {{
            x = (x + 1) % 256; j = (j + S[x]) % 256;
            int t = S[x]; S[x] = S[j]; S[j] = t;
            r[n] = (byte)(data[n] ^ S[(S[x] + S[j]) % 256]);
        }}
        return r;
    }}"""

_CS_AES_FN = """\
    static byte[] {fn}(byte[] data, byte[] key, byte[] iv) {{
        using (var aes = System.Security.Cryptography.Aes.Create()) {{
            aes.KeySize = 256; aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.Key = key; aes.IV = iv;
            using (var dec = aes.CreateDecryptor())
            using (var ms = new System.IO.MemoryStream(data))
            using (var cs = new System.Security.Cryptography.CryptoStream(ms, dec, System.Security.Cryptography.CryptoStreamMode.Read))
            using (var out_ = new System.IO.MemoryStream()) {{
                cs.CopyTo(out_); return out_.ToArray();
            }}
        }}
    }}"""

_CS_ROT_FN = """\
    static byte[] {fn}(byte[] data, int n) {{
        byte[] r = new byte[data.Length];
        for (int i = 0; i < data.Length; i++) r[i] = (byte)((data[i] + n) % 256);
        return r;
    }}"""


# ---------------------------------------------------------------------------
# VBA stub templates
# ---------------------------------------------------------------------------

_VBA_XOR1_FN = """\
Private Function {fn}(ByRef data() As Byte, ByVal k As Byte) As Byte()
    Dim i As Long
    For i = 0 To UBound(data)
        data(i) = data(i) Xor k
    Next i
    {fn} = data
End Function"""

_VBA_XORN_FN = """\
Private Function {fn}(ByRef data() As Byte, ByRef k() As Byte) As Byte()
    Dim i As Long, kl As Long
    kl = UBound(k) + 1
    For i = 0 To UBound(data)
        data(i) = data(i) Xor k(i Mod kl)
    Next i
    {fn} = data
End Function"""

_VBA_RC4_FN = """\
Private Function {fn}(ByRef data() As Byte, ByRef key() As Byte) As Byte()
    Dim S(255) As Integer, i As Long, j As Long, tmp As Integer
    Dim kl As Long: kl = UBound(key) + 1
    For i = 0 To 255: S(i) = i: Next i
    j = 0
    For i = 0 To 255
        j = (j + S(i) + key(i Mod kl)) Mod 256
        tmp = S(i): S(i) = S(j): S(j) = tmp
    Next i
    ReDim r(UBound(data)) As Byte
    i = 0: j = 0
    Dim n As Long
    For n = 0 To UBound(data)
        i = (i + 1) Mod 256: j = (j + S(i)) Mod 256
        tmp = S(i): S(i) = S(j): S(j) = tmp
        r(n) = data(n) Xor S((S(i) + S(j)) Mod 256)
    Next n
    {fn} = r
End Function"""

_VBA_ROT_FN = """\
Private Function {fn}(ByRef data() As Byte, ByVal n As Integer) As Byte()
    Dim i As Long
    ReDim r(UBound(data)) As Byte
    For i = 0 To UBound(data)
        r(i) = CByte((CInt(data(i)) + n) Mod 256)
    Next i
    {fn} = r
End Function"""
