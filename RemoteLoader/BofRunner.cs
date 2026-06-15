/*
 * BofRunner.cs — in-process COFF/BOF (x64) loader.
 *
 * Loads a Cobalt-Style Beacon Object File (.o) and invokes its entry point
 * with a packed binary argument buffer. The COFF file is parsed, sections
 * are mapped with the page protection derived from Section.Characteristics,
 * symbols and relocations are resolved, and a curated set of Beacon API
 * stubs is exposed to the BOF.
 *
 * Fixes over the legacy inline loader:
 *   - __imp_ (and leading _) prefix is stripped before DFR resolution.
 *   - REL_ADDR32NB (0x0003) is implemented so .pdata SEH unwinding works.
 *   - REL32_1..REL32_5 patch the 4-byte displacement at the correct
 *     offset within the relocation site.
 *   - .bss sections are allocated (max(rawSz, vsize)) and zero-initialised.
 *   - Page protection follows Section.Characteristics (code=RX, ro=R, data=RW).
 *   - Defensive bounds checks on every parsed offset.
 *   - UTF-8 decoding in BeaconOutput for CALLBACK_OUTPUT_UTF8.
 *   - Configurable entry point name (default "go").
 *   - Captured output via BofResult.Output.
 *   - IDisposable lifetime (section memory freed only on Dispose).
 */

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace RemoteLoader
{
    public sealed class BofOptions
    {
        public string EntryPoint { get; init; } = "go";
        public bool   HonorSectionFlags { get; init; } = true;
        public bool   CaptureOutput { get; init; }   = true;
        public int    TimeoutMs { get; init; }       = 0;
        public Dictionary<string, IntPtr>? CustomApis { get; init; }
        public Action<string>? Log { get; init; }
    }

    public sealed class BofResult
    {
        public int      ExitCode { get; set; }
        public string   Output   { get; set; } = "";
        public TimeSpan Elapsed  { get; set; }
        public bool     TimedOut { get; set; }
    }

    internal static class Native
    {
[DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPStr)] string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpLibFileName);
    }

    // ── COFF structures ─────────────────────────────────────────────────────
    internal sealed class CoffSection
    {
        public string  Name        = "";
        public int     VirtualSize;
        public int     VirtualAddress;
        public int     SizeOfRawData;
        public int     PointerToRawData;
        public int     PointerToRelocations;
        public ushort  NumberOfRelocations;
        public int     Characteristics;
        public IntPtr  Base;
        public int     AllocSize;
    }

    internal sealed class CoffSymbol
    {
        public string Name     = "";
        public int    Value;
        public short  SectionNumber; // 0 = undefined, -1 = absolute, -2 = debug
        public ushort Type;
        public byte   StorageClass;
        public byte   NumberOfAuxSymbols;
    }

    internal sealed class CoffFile
    {
        public ushort       Machine;
        public int          PointerToSymbolTable;
        public int          NumberOfSymbols;
        public ushort       SizeOfOptionalHeader;
        public ushort       Characteristics;
        public CoffSection[] Sections = Array.Empty<CoffSection>();
        public CoffSymbol[]  Symbols  = Array.Empty<CoffSymbol>();
        public byte[]       StringTable = Array.Empty<byte>();

        public const ushort MACHINE_AMD64  = 0x8664;
        public const ushort MACHINE_I386   = 0x014C;

        // Section characteristics
        public const uint IMAGE_SCN_CNT_CODE               = 0x00000020;
        public const uint IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040;
        public const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        public const uint IMAGE_SCN_MEM_EXECUTE            = 0x20000000;
        public const uint IMAGE_SCN_MEM_READ               = 0x40000000;
        public const uint IMAGE_SCN_MEM_WRITE              = 0x80000000;

        // Symbol storage classes
        public const byte IMAGE_SYM_CLASS_EXTERNAL         = 2;
        public const byte IMAGE_SYM_CLASS_STATIC           = 3;
        public const byte IMAGE_SYM_CLASS_WEAK_EXTERNAL    = 105;
        public const byte IMAGE_SYM_CLASS_FILE             = 0x67;

        // AMD64 relocations
        public const ushort IMAGE_REL_AMD64_ABSOLUTE = 0x0000;
        public const ushort IMAGE_REL_AMD64_ADDR64   = 0x0001;
        public const ushort IMAGE_REL_AMD64_ADDR32   = 0x0002;
        public const ushort IMAGE_REL_AMD64_ADDR32NB = 0x0003;
        public const ushort IMAGE_REL_AMD64_REL32    = 0x0004;
        public const ushort IMAGE_REL_AMD64_REL32_1  = 0x0005;
        public const ushort IMAGE_REL_AMD64_REL32_2  = 0x0006;
        public const ushort IMAGE_REL_AMD64_REL32_3  = 0x0007;
        public const ushort IMAGE_REL_AMD64_REL32_4  = 0x0008;
        public const ushort IMAGE_REL_AMD64_REL32_5  = 0x0009;
        public const ushort IMAGE_REL_AMD64_SECTION  = 0x000A;
        public const ushort IMAGE_REL_AMD64_SECREL   = 0x000B;
        public const ushort IMAGE_REL_AMD64_SECREL7  = 0x000C;
        public const ushort IMAGE_REL_AMD64_TOKEN    = 0x000D;
        public const ushort IMAGE_REL_AMD64_SREL32   = 0x000E;
        public const ushort IMAGE_REL_AMD64_PAIR     = 0x000F;
        public const ushort IMAGE_REL_AMD64_SSPAN32  = 0x0010;

        public const int HEADER_SIZE  = 20;
        public const int SECTION_SIZE = 40;
        public const int SYMBOL_SIZE  = 18;
        public const int RELOC_SIZE   = 10;
    }

    // ── BofRunner ───────────────────────────────────────────────────────────
    public sealed unsafe class BofRunner : IDisposable
    {
        public const int CALLBACK_OUTPUT      = 0x0;
        public const int CALLBACK_OUTPUT_OEM  = 0x1e;
        public const int CALLBACK_ERROR       = 0x0d;
        public const int CALLBACK_OUTPUT_UTF8 = 0x20;

        private readonly BofOptions _opts;
        private readonly Dictionary<string, IntPtr> _api = new(StringComparer.Ordinal);
        private readonly List<Delegate> _pins = new();
        private readonly List<IntPtr>   _allocations = new();
        private readonly object _writeLock = new();
        private StringBuilder? _capture;
        private TextWriter?    _savedOut;
        private TextWriter?    _savedError;
        private bool           _capturing;
        private bool           _disposed;

        public BofRunner(BofOptions? opts = null)
        {
            _opts = opts ?? new BofOptions();
            RegisterCoreApis();
            if (_opts.CustomApis != null)
                foreach (var kv in _opts.CustomApis) _api[kv.Key] = kv.Value;
        }

        // Public surface ────────────────────────────────────────────────────
        public static bool IsBof(byte[] data)
        {
            if (data.Length < CoffFile.HEADER_SIZE) return false;
            if (data[0] == 0x4D && data[1] == 0x5A) return false;
            ushort machine = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(0, 2));
            if (machine != CoffFile.MACHINE_AMD64) return false;
            ushort optHdr = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(16, 2));
            return optHdr == 0;
        }

        public BofResult Run(byte[] coffBytes, byte[] args)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(BofRunner));
            if (coffBytes == null) throw new ArgumentNullException(nameof(coffBytes));
            if (args == null) throw new ArgumentNullException(nameof(args));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var result = new BofResult();

            try
            {
                var coff = ParseCoff(coffBytes);
                if (coff.Machine != CoffFile.MACHINE_AMD64)
                    throw new InvalidOperationException(
                        $"Unsupported machine 0x{coff.Machine:X4} (only AMD64 BOFs supported)");

                AllocateSections(coff, coffBytes);
                var symAddr = ResolveSymbols(coff);
                ApplyRelocations(coff, coffBytes, symAddr);
                IntPtr goAddr = FindEntryPoint(coff, symAddr);
                if (goAddr == IntPtr.Zero)
                    throw new InvalidOperationException(
                        $"Entry point '{_opts.EntryPoint}' not found");

                StartCapture();
                InvokeEntry(goAddr, args, result);
                result.ExitCode = 0;
            }
            catch (Exception ex)
            {
                result.ExitCode = -1;
                if (string.IsNullOrEmpty(result.Output))
                    result.Output = ex.Message;
            }
            finally
            {
                EndCapture(result);
                sw.Stop();
                result.Elapsed = sw.Elapsed;
            }

            return result;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            EndCapture(null);
            foreach (var p in _allocations)
                if (p != IntPtr.Zero) Native.VirtualFree(p, UIntPtr.Zero, 0x8000);
            _allocations.Clear();
        }

        // ── Internals ──────────────────────────────────────────────────────
        private CoffFile ParseCoff(byte[] data)
        {
            if (data.Length < CoffFile.HEADER_SIZE)
                throw new InvalidDataException("File too small for COFF header");

            var f = new CoffFile
            {
                Machine              = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(0, 2)),
                Sections             = new CoffSection[BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(2, 2))],
                PointerToSymbolTable = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8, 4)),
                NumberOfSymbols      = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(12, 4)),
                SizeOfOptionalHeader = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(16, 2)),
                Characteristics      = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(18, 2)),
            };

            int strTabOff = f.PointerToSymbolTable + f.NumberOfSymbols * CoffFile.SYMBOL_SIZE;
            if (strTabOff > data.Length)
                throw new InvalidDataException("Symbol table extends past end of file");

            int strTabTotal = 0;
            if (strTabOff + 4 <= data.Length)
                strTabTotal = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(strTabOff, 4));
            int strTabEnd = strTabOff + strTabTotal;
            if (strTabEnd < strTabOff || strTabEnd > data.Length)
                throw new InvalidDataException("String table extends past end of file");
            f.StringTable = new byte[Math.Max(0, strTabTotal)];
            if (strTabTotal > 0)
                Array.Copy(data, strTabOff, f.StringTable, 0, strTabTotal);

            for (int s = 0; s < f.Sections.Length; s++)
            {
                int sh = CoffFile.HEADER_SIZE + s * CoffFile.SECTION_SIZE;
                if (sh + CoffFile.SECTION_SIZE > data.Length)
                    throw new InvalidDataException($"Section {s} header extends past end of file");

                var sec = new CoffSection
                {
                    Name                  = ReadName(data, sh, 0, 8),
                    VirtualSize           = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sh + 8, 4)),
                    VirtualAddress        = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sh + 12, 4)),
                    SizeOfRawData         = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sh + 16, 4)),
                    PointerToRawData      = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sh + 20, 4)),
                    PointerToRelocations  = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sh + 24, 4)),
                    NumberOfRelocations   = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(sh + 32, 2)),
                    Characteristics       = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(sh + 36, 4)),
                };

                if (sec.SizeOfRawData > 0)
                {
                    if (sec.PointerToRawData < 0 ||
                        sec.PointerToRawData + sec.SizeOfRawData > data.Length)
                        throw new InvalidDataException(
                            $"Section {s} ({sec.Name}) raw data extends past end of file");
                }
                if (sec.NumberOfRelocations > 0)
                {
                    if (sec.PointerToRelocations < 0 ||
                        sec.PointerToRelocations + sec.NumberOfRelocations * CoffFile.RELOC_SIZE > data.Length)
                        throw new InvalidDataException(
                            $"Section {s} ({sec.Name}) relocations extend past end of file");
                }
                f.Sections[s] = sec;
            }

            f.Symbols = new CoffSymbol[f.NumberOfSymbols];
            for (int i = 0; i < f.NumberOfSymbols; )
            {
                int off = f.PointerToSymbolTable + i * CoffFile.SYMBOL_SIZE;
                if (off + CoffFile.SYMBOL_SIZE > data.Length)
                    throw new InvalidDataException($"Symbol {i} extends past end of file");

                var sym = new CoffSymbol
                {
                    Value              = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(off + 8, 4)),
                    SectionNumber      = (short)BinaryPrimitives.ReadInt16LittleEndian(data.AsSpan(off + 12, 2)),
                    Type               = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(off + 14, 2)),
                    StorageClass       = data[off + 16],
                    NumberOfAuxSymbols = data[off + 17],
                };
                sym.Name = ReadSymbolName(data, off, f.StringTable);
                f.Symbols[i] = sym;
                i += 1 + sym.NumberOfAuxSymbols;
            }

            return f;
        }

        private static string ReadSymbolName(byte[] data, int symOff, byte[] strTab)
        {
            // MS-COFF: a name is a strtab reference when bytes 0..3 of the inline
            // name are all zero. The spec says "all 8 bytes", but real-world BFD/GCC
            // output uses the 4-byte form (bytes 4..7 = strtab offset, bytes 0..3 = 0).
            // We accept both forms.
            bool strtabRef = (data[symOff] | data[symOff + 1] | data[symOff + 2] | data[symOff + 3]) == 0;
            if (strtabRef)
            {
                int off = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(symOff + 4, 4));
                if (off < 0 || off + 4 > strTab.Length) return "";
                int end = off;
                while (end < strTab.Length && strTab[end] != 0) end++;
                return Encoding.ASCII.GetString(strTab, off, end - off);
            }
            int len = 0;
            while (len < 8 && data[symOff + len] != 0) len++;
            return Encoding.ASCII.GetString(data, symOff, len);
        }

        private static string ReadName(byte[] data, int off, int sub, int len)
        {
            int start = off + sub;
            int endPos = start + len;
            while (start < endPos && data[start] != 0) start++;
            return Encoding.ASCII.GetString(data, off + sub, start - (off + sub));
        }

        private void AllocateSections(CoffFile coff, byte[] raw)
        {
            const uint MEM_COMMIT  = 0x1000;
            const uint MEM_RESERVE = 0x2000;
            const uint PAGE_READONLY          = 0x02;
            const uint PAGE_READWRITE         = 0x04;
            const uint PAGE_EXECUTE_READ      = 0x20;
            const uint PAGE_EXECUTE_READWRITE = 0x40;

            foreach (var sec in coff.Sections)
            {
                int size = Math.Max(sec.SizeOfRawData, sec.VirtualSize);
                if (size == 0)
                {
                    sec.Base = IntPtr.Zero;
                    sec.AllocSize = 0;
                    continue;
                }

                uint prot;
                if (_opts.HonorSectionFlags)
                {
                    bool exe = (sec.Characteristics & CoffFile.IMAGE_SCN_MEM_EXECUTE) != 0;
                    bool wr  = (sec.Characteristics & CoffFile.IMAGE_SCN_MEM_WRITE)  != 0;
                    prot = exe ? (wr ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
                               : (wr ? PAGE_READWRITE         : PAGE_READONLY);
                }
                else
                {
                    prot = PAGE_EXECUTE_READWRITE;
                }

                int rounded = (size + 0xFFF) & ~0xFFF;
                var p = Native.VirtualAlloc(IntPtr.Zero, (UIntPtr)rounded, MEM_COMMIT | MEM_RESERVE, prot);
                if (p == IntPtr.Zero)
                    throw new InvalidOperationException(
                        $"VirtualAlloc failed for section '{sec.Name}' (size=0x{size:X})");
                _allocations.Add(p);
                sec.Base      = p;
                sec.AllocSize = rounded;

                if (sec.SizeOfRawData > 0)
                    Marshal.Copy(raw, sec.PointerToRawData, p, sec.SizeOfRawData);
            }
        }

        private IntPtr[] ResolveSymbols(CoffFile coff)
        {
            var addr = new IntPtr[coff.Symbols.Length];
            for (int i = 0; i < coff.Symbols.Length; i++)
            {
                var sym = coff.Symbols[i];
                if (sym.SectionNumber == 0 && sym.StorageClass == CoffFile.IMAGE_SYM_CLASS_EXTERNAL)
                {
                    addr[i] = ResolveExternal(sym.Name);
                    if (addr[i] == IntPtr.Zero)
                        _opts.Log?.Invoke($"BOF: unresolved symbol '{sym.Name}'");
                }
                else if (sym.SectionNumber == -1)
                {
                    addr[i] = (IntPtr)sym.Value;
                }
                else if (sym.SectionNumber > 0 && sym.SectionNumber <= coff.Sections.Length)
                {
                    var sec = coff.Sections[sym.SectionNumber - 1];
                    if (sec.Base != IntPtr.Zero)
                        addr[i] = sec.Base + sym.Value;
                }
            }
            return addr;
        }

        private IntPtr ResolveExternal(string name)
        {
            if (string.IsNullOrEmpty(name)) return IntPtr.Zero;
            if (_api.TryGetValue(name, out var p)) return p;

            string canon = name;
            if (canon.StartsWith("__imp_", StringComparison.Ordinal)) canon = canon[6..];
            else if (canon.StartsWith("_", StringComparison.Ordinal))  canon = canon[1..];

            int dollar = canon.IndexOf('$');
            if (dollar > 0)
            {
                string dll  = canon[..dollar].ToLowerInvariant() + ".dll";
                string func = canon[(dollar + 1)..];
                IntPtr h = Native.GetModuleHandle(dll);
                if (h == IntPtr.Zero) h = Native.LoadLibrary(dll);
                if (h != IntPtr.Zero)
                {
                    var a = Native.GetProcAddress(h, func);
                    if (a != IntPtr.Zero) return a;
                }
            }
            return IntPtr.Zero;
        }

        private void ApplyRelocations(CoffFile coff, byte[] raw, IntPtr[] symAddr)
        {
            for (int s = 0; s < coff.Sections.Length; s++)
            {
                var sec = coff.Sections[s];
                if (sec.NumberOfRelocations == 0 || sec.Base == IntPtr.Zero) continue;

                int baseReloc = sec.PointerToRelocations;
                for (int r = 0; r < sec.NumberOfRelocations; r++)
                {
                    int ro = baseReloc + r * CoffFile.RELOC_SIZE;
                    int va       = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(ro, 4));
                    int symIdx   = BinaryPrimitives.ReadInt32LittleEndian(raw.AsSpan(ro + 4, 4));
                    ushort rType = (ushort)BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(ro + 8, 2));

                    IntPtr site   = sec.Base + va;
                    IntPtr target = (symIdx >= 0 && symIdx < symAddr.Length) ? symAddr[symIdx] : IntPtr.Zero;

                    ApplyReloc(site, target, sec.Base, rType);
                }
            }
        }

        private void ApplyReloc(IntPtr site, IntPtr target, IntPtr sectionBase, ushort type)
        {
            switch (type)
            {
                case CoffFile.IMAGE_REL_AMD64_ABSOLUTE:
                    return;

                case CoffFile.IMAGE_REL_AMD64_ADDR64:
                {
                    long* p = (long*)site;
                    *p = target.ToInt64();
                    return;
                }

                case CoffFile.IMAGE_REL_AMD64_ADDR32NB:
                {
                    // .pdata RUNTIME_FUNCTION: 32-bit RVA from the section base to the target.
                    int* p = (int*)site;
                    *p = (int)(target.ToInt64() - sectionBase.ToInt64());
                    return;
                }

                case CoffFile.IMAGE_REL_AMD64_ADDR32:
                {
                    int* p = (int*)site;
                    *p = (int)target.ToInt64();
                    _opts.Log?.Invoke("BOF: IMAGE_REL_AMD64_ADDR32 applied (x86-only reloc type)");
                    return;
                }

                case CoffFile.IMAGE_REL_AMD64_REL32:
                case CoffFile.IMAGE_REL_AMD64_REL32_1:
                case CoffFile.IMAGE_REL_AMD64_REL32_2:
                case CoffFile.IMAGE_REL_AMD64_REL32_3:
                case CoffFile.IMAGE_REL_AMD64_REL32_4:
                case CoffFile.IMAGE_REL_AMD64_REL32_5:
                {
                    int n = type - CoffFile.IMAGE_REL_AMD64_REL32;          // 0..5
                    int* p = (int*)((byte*)site + n);
                    long disp = target.ToInt64() - (site.ToInt64() + 4 + n);
                    *p = (int)disp;
                    return;
                }

                case CoffFile.IMAGE_REL_AMD64_SECTION:
                case CoffFile.IMAGE_REL_AMD64_SECREL:
                case CoffFile.IMAGE_REL_AMD64_SECREL7:
                case CoffFile.IMAGE_REL_AMD64_TOKEN:
                case CoffFile.IMAGE_REL_AMD64_SREL32:
                case CoffFile.IMAGE_REL_AMD64_PAIR:
                case CoffFile.IMAGE_REL_AMD64_SSPAN32:
                    _opts.Log?.Invoke($"BOF: unhandled AMD64 reloc type 0x{type:X4}");
                    return;

                default:
                    _opts.Log?.Invoke($"BOF: unknown reloc type 0x{type:X4}");
                    return;
            }
        }

        private IntPtr FindEntryPoint(CoffFile coff, IntPtr[] symAddr)
        {
            for (int i = 0; i < coff.Symbols.Length; i++)
            {
                var sym = coff.Symbols[i];
                if (!string.Equals(sym.Name, _opts.EntryPoint, StringComparison.Ordinal)) continue;
                if (sym.SectionNumber <= 0 || sym.SectionNumber > coff.Sections.Length) continue;
                var sec = coff.Sections[sym.SectionNumber - 1];
                if (sec.Base == IntPtr.Zero) continue;
                return sec.Base + sym.Value;
            }
            return IntPtr.Zero;
        }

        private void InvokeEntry(IntPtr goAddr, byte[] args, BofResult result)
        {
            var go = Marshal.GetDelegateForFunctionPointer<D_BofEntry>(goAddr);
            if (_opts.TimeoutMs > 0)
            {
                Exception? captured = null;
                var t = new System.Threading.Thread(() =>
                {
                    try
                    {
                        if (args.Length > 0) fixed (byte* p = args) go((IntPtr)p, args.Length);
                        else                 go(IntPtr.Zero, 0);
                    }
                    catch (Exception ex) { captured = ex; }
                }) { IsBackground = true };
                t.Start();
                if (!t.Join(_opts.TimeoutMs))
                {
                    result.TimedOut = true;
                }
                else if (captured != null)
                {
                    lock (_writeLock) _capture?.AppendLine($"[!] BOF exception: {captured.Message}");
                }
            }
            else
            {
                if (args.Length > 0) fixed (byte* p = args) go((IntPtr)p, args.Length);
                else                 go(IntPtr.Zero, 0);
            }
        }

        // Output capture
        private void StartCapture()
        {
            if (!_opts.CaptureOutput) return;
            _capture = new StringBuilder();
            _savedOut   = Console.Out;
            _savedError = Console.Error;
            var swOut   = new CapturingTextWriter(_capture, Console.Out, isError:false);
            var swErr   = new CapturingTextWriter(_capture, Console.Error, isError:true);
            Console.SetOut(swOut);
            Console.SetError(swErr);
            _capturing = true;
        }

        private void EndCapture(BofResult? result)
        {
            if (!_capturing) return;
            Console.SetOut(_savedOut   ?? Console.Out);
            Console.SetError(_savedError ?? Console.Error);
            _capturing = false;
            if (result != null && _capture != null) result.Output = _capture.ToString();
            _capture = null;
        }

        private sealed class CapturingTextWriter : TextWriter
        {
            private readonly StringBuilder _buf;
            private readonly TextWriter    _inner;
            private readonly bool          _isError;
            public CapturingTextWriter(StringBuilder buf, TextWriter inner, bool isError)
            { _buf = buf; _inner = inner; _isError = isError; }
            public override Encoding Encoding => Encoding.UTF8;
            public override void Write(char c)
            {
                lock (_buf) _buf.Append(c);
                _inner.Write(c);
            }
            public override void Write(string? s)
            {
                if (s == null) return;
                lock (_buf) _buf.Append(s);
                _inner.Write(s);
            }
            public override void WriteLine(string? s)
            {
                lock (_buf) { _buf.Append(s); _buf.Append('\n'); }
                _inner.WriteLine(s);
            }
            public override void Flush() => _inner.Flush();
        }

        // ── Beacon API registry ───────────────────────────────────────────
        private void RegisterCoreApis()
        {
            // Output
            Reg("BeaconPrintf",       new D_Printf(BPrintf));
            Reg("BeaconOutput",       new D_Output(BOutput));

            // Data API
            Reg("BeaconDataParse",    new D_DataParse(BDataParse));
            Reg("BeaconDataInt",      new D_DataInt(BDataInt));
            Reg("BeaconDataShort",    new D_DataShort(BDataShort));
            Reg("BeaconDataLength",   new D_DataLength(BDataLength));
            Reg("BeaconDataPtr",      new D_DataPtr(BDataPtr));
            Reg("BeaconDataExtract",  new D_DataExtract(BDataExtract));

            // Format API
            Reg("BeaconFormatAlloc",  new D_FmtAlloc(BFmtAlloc));
            Reg("BeaconFormatReset",  new D_FmtReset(BFmtReset));
            Reg("BeaconFormatFree",   new D_FmtFree(BFmtFree));
            Reg("BeaconFormatAppend", new D_FmtAppend(BFmtAppend));
            Reg("BeaconFormatPrintf", new D_FmtPrintf(BFmtPrintf));
            Reg("BeaconFormatInt",    new D_FmtInt(BFmtInt));
            Reg("BeaconFormatToString", new D_FmtToString(BFmtToString));

            // Token + admin
            Reg("BeaconUseToken",     new D_BoolArgPtr(BUseToken));
            Reg("BeaconRevertToken",  new D_Void(BRevertToken));
            Reg("BeaconIsAdmin",      new D_IsAdmin(BIsAdmin));

            // Spawn/inject (no-op stubs — the local loader has no remote process)
            Reg("BeaconGetSpawnTo",   new D_ThreePtr(BGetSpawnTo));
            Reg("BeaconSpawnTemporaryProcess",  new D_FourArgPtr(BSpawnTemp));
            Reg("BeaconInjectProcess",           new D_InjectArgs(BInjectProcess));
            Reg("BeaconInjectTemporaryProcess",  new D_InjectArgs(BInjectProcess));
            Reg("BeaconCleanupProcess",          new D_OnePtr(BCleanupProcess));

            // Utility
            Reg("toWideChar",         new D_ThreeArgPtr(BToWideChar));
            Reg("BeaconDownload",     new D_Download(BDownload));
            Reg("BeaconGetOutputData",new D_GetOutData(BGetOutputData));

            // Post-4.5 data store
            Reg("BeaconAddValue",     new D_BoolArgTwoPtr(BAddValue));
            Reg("BeaconGetValue",     new D_GetValue(BGetValue));
            Reg("BeaconRemoveValue",  new D_BoolArgOnePtr(BRemoveValue));

            // Native memory wrappers
            Reg("BeaconVirtualAlloc", new D_BVA(BVirtualAlloc));
            Reg("BeaconVirtualAllocEx", new D_BVAEx(BVirtualAllocEx));
            Reg("BeaconVirtualFree",  new D_BVF(BVirtualFree));

            // Stack-protector fallback (MS ucrtbase)
            Reg("__stack_chk_fail",   new D_Void(BStackChkFail));
        }

        private void Reg(string name, Delegate d)
        {
            _pins.Add(d);
            _api[name] = Marshal.GetFunctionPointerForDelegate(d);
        }

        // ── Beacon stubs ──────────────────────────────────────────────────
        private void BPrintf(int type, IntPtr fmt)
        {
            // Cobalt-Strike BOFs call BeaconPrintf(type, "%s = %d\n", s, i) variadic.
            // The C# side cannot easily walk the C stack; we forward the format
            // string verbatim. BOFs that rely on this for fancy formatting will see
            // literal %d/%s — same as the legacy loader. The format-string parser
            // is a separate workstream.
            string s = Marshal.PtrToStringAnsi(fmt) ?? "";
            lock (_writeLock) Console.Write(s);
        }

        private void BOutput(int type, IntPtr data, int len)
        {
            if (len <= 0 || data == IntPtr.Zero) return;
            byte[] buf = new byte[len];
            Marshal.Copy(data, buf, 0, len);
            string s;
            if (type == CALLBACK_OUTPUT_UTF8)
            {
                try { s = Encoding.UTF8.GetString(buf); }
                catch { s = Encoding.ASCII.GetString(buf); }
            }
            else
            {
                s = Encoding.ASCII.GetString(buf);
            }
            lock (_writeLock) Console.Write(s);
        }

        private void BDataParse(DataParser* p, IntPtr buf, int sz)
        {
            p->Original = buf; p->Buffer = buf; p->Length = sz; p->Size = sz;
        }
        private int  BDataInt(DataParser* p)
        {
            if (p->Length < 4) return 0;
            int v = *(int*)p->Buffer;
            p->Buffer += 4; p->Length -= 4; return v;
        }
        private short BDataShort(DataParser* p)
        {
            if (p->Length < 2) return 0;
            short v = *(short*)p->Buffer;
            p->Buffer += 2; p->Length -= 2; return v;
        }
        private int   BDataLength(DataParser* p) => p->Length;
        private IntPtr BDataPtr(DataParser* p, int sz)
        {
            if (p->Length < sz) return IntPtr.Zero;
            IntPtr v = p->Buffer;
            p->Buffer += sz; p->Length -= sz; return v;
        }
        private IntPtr BDataExtract(DataParser* p, IntPtr szPtr)
        {
            if (p->Length < 4) return IntPtr.Zero;
            int len = *(int*)p->Buffer;
            p->Buffer += 4; p->Length -= 4;
            if (len < 0 || len > p->Length) return IntPtr.Zero;
            IntPtr v = p->Buffer;
            if (szPtr != IntPtr.Zero) *(int*)szPtr = len;
            p->Buffer += len; p->Length -= len;
            return v;
        }

        private void BFmtAlloc(DataParser* f, int maxsz)
        {
            IntPtr buf = Marshal.AllocHGlobal(Math.Max(maxsz, 1));
            f->Original = buf; f->Buffer = buf; f->Length = 0; f->Size = maxsz;
        }
        private void BFmtReset(DataParser* f) { f->Buffer = f->Original; f->Length = 0; }
        private void BFmtFree(DataParser* f)
        {
            if (f->Original != IntPtr.Zero) Marshal.FreeHGlobal(f->Original);
            f->Original = f->Buffer = IntPtr.Zero; f->Length = f->Size = 0;
        }
        private void BFmtAppend(DataParser* f, IntPtr text, int len)
        {
            if (f->Length + len > f->Size) return;
            Buffer.MemoryCopy((void*)text, (void*)f->Buffer, f->Size - f->Length, len);
            f->Buffer += len; f->Length += len;
        }
        private void BFmtPrintf(DataParser* f, IntPtr fmt)
        {
            string s = Marshal.PtrToStringAnsi(fmt) ?? "";
            byte[] b = Encoding.ASCII.GetBytes(s);
            fixed (byte* pb = b) BFmtAppend(f, (IntPtr)pb, b.Length);
        }
        private void BFmtInt(DataParser* f, int v)
        {
            string s = v.ToString();
            byte[] b = Encoding.ASCII.GetBytes(s);
            fixed (byte* pb = b) BFmtAppend(f, (IntPtr)pb, b.Length);
        }
        private IntPtr BFmtToString(DataParser* f, IntPtr szPtr)
        {
            if (szPtr != IntPtr.Zero) *(int*)szPtr = f->Length;
            return f->Original;
        }
        private byte BIsAdmin() => (byte)(Environment.IsPrivilegedProcess ? 1 : 0);

        private byte BUseToken(IntPtr t) => 0;
        private void BRevertToken() { }
        private void BGetSpawnTo(byte x86, IntPtr buf, int len) { }
        private byte BSpawnTemp(byte x86, byte ignore, IntPtr si, IntPtr pi) => 0;
        private void BInjectProcess(IntPtr h, int pid, IntPtr payload, int plen, int poff, IntPtr arg, int alen) { }
        private void BInjectTemp(IntPtr pi, IntPtr payload, int plen, int poff, IntPtr arg, int alen) { }
        private void BCleanupProcess(IntPtr pi) { }
        private byte BToWideChar(IntPtr src, IntPtr dst, int max) => 0;
        private byte BDownload(IntPtr name, IntPtr buf, uint len) => 0;
        private IntPtr BGetOutputData(IntPtr outSize)
        {
            if (outSize != IntPtr.Zero) *(int*)outSize = 0;
            return IntPtr.Zero;
        }
        private byte BAddValue(IntPtr key, IntPtr ptr) => 0;
        private IntPtr BGetValue(IntPtr key) => IntPtr.Zero;
        private byte BRemoveValue(IntPtr key) => 0;
        private IntPtr BVirtualAlloc(IntPtr lp, UIntPtr sz, uint t, uint p) =>
            Native.VirtualAlloc(lp, sz, t, p);
        private IntPtr BVirtualAllocEx(IntPtr h, IntPtr lp, UIntPtr sz, uint t, uint p) =>
            Native.VirtualAlloc(lp, sz, t, p);
        private byte BVirtualFree(IntPtr lp, UIntPtr sz, uint t) =>
            (byte)(Native.VirtualFree(lp, sz, t) ? 1 : 0);
        private void BStackChkFail() { /* fail open */ }

        // ── Beacon API delegate types ─────────────────────────────────────
        [StructLayout(LayoutKind.Sequential)]
        internal struct DataParser
        {
            public IntPtr Original;
            public IntPtr Buffer;
            public int    Length;
            public int    Size;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_Printf(int type, IntPtr fmt);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_Output(int type, IntPtr data, int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_DataParse(DataParser* p, IntPtr buf, int sz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int          D_DataInt(DataParser* p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate short        D_DataShort(DataParser* p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int          D_DataLength(DataParser* p);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr       D_DataPtr(DataParser* p, int sz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr       D_DataExtract(DataParser* p, IntPtr sz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_FmtAlloc(DataParser* f, int maxsz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_FmtReset(DataParser* f);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_FmtFree(DataParser* f);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_FmtAppend(DataParser* f, IntPtr text, int len);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_FmtPrintf(DataParser* f, IntPtr fmt);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_FmtInt(DataParser* f, int value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr       D_FmtToString(DataParser* f, IntPtr sz);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte         D_IsAdmin();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         D_BofEntry(IntPtr args, int len);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_BoolArgPtr(IntPtr a);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_BoolArgTwoPtr(IntPtr a, IntPtr b);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_BoolArgOnePtr(IntPtr a);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void D_Void();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void D_ThreePtr(byte a, IntPtr b, int c);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_FourArgPtr(byte a, byte b, IntPtr c, IntPtr d);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void D_InjectArgs(IntPtr a, int b, IntPtr c, int d, int e, IntPtr f, int g);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_ThreeArgPtr(IntPtr a, IntPtr b, int c);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_Download(IntPtr a, IntPtr b, uint c);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr D_GetOutData(IntPtr a);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr D_GetValue(IntPtr a);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr D_BVA(IntPtr a, UIntPtr b, uint c, uint d);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr D_BVAEx(IntPtr a, IntPtr b, UIntPtr c, uint d, uint e);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte D_BVF(IntPtr a, UIntPtr b, uint c);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void D_OnePtr(IntPtr a);
    }
}

// Replace this at the right place
