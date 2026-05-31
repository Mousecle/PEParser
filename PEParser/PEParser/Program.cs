using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct DosHeader
{
    public ushort e_magic;
    public ushort e_cblp, e_cp, e_crlc, e_cparhdr;
    public ushort e_minalloc, e_maxalloc;
    public ushort e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public ushort[] e_res;
    public ushort e_oemid, e_oeminfo;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public ushort[] e_res2;
    public uint e_lfanew;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct FileHeader
{
    public ushort Machine;
    public ushort NumberOfSections;
    public uint TimeDateStamp;
    public uint PointerToSymbolTable;
    public uint NumberOfSymbols;
    public ushort SizeOfOptionalHeader;
    public ushort Characteristics;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct DataDirectory
{
    public uint VirtualAddress;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct OptionalHeader32
{
    public ushort Magic;
    public byte MajorLinkerVersion, MinorLinkerVersion;
    public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    public uint AddressOfEntryPoint, BaseOfCode, BaseOfData;
    public uint ImageBase;
    public uint SectionAlignment, FileAlignment;
    public ushort MajorOSVersion, MinorOSVersion;
    public ushort MajorImageVersion, MinorImageVersion;
    public ushort MajorSubsystemVersion, MinorSubsystemVersion;
    public uint Win32VersionValue;
    public uint SizeOfImage, SizeOfHeaders, CheckSum;
    public ushort Subsystem, DllCharacteristics;
    public uint SizeOfStackReserve, SizeOfStackCommit;
    public uint SizeOfHeapReserve, SizeOfHeapCommit;
    public uint LoaderFlags, NumberOfRvaAndSizes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public DataDirectory[] Dirs;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct OptionalHeader64
{
    public ushort Magic;
    public byte MajorLinkerVersion, MinorLinkerVersion;
    public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    public uint AddressOfEntryPoint, BaseOfCode;
    public ulong ImageBase;
    public uint SectionAlignment, FileAlignment;
    public ushort MajorOSVersion, MinorOSVersion;
    public ushort MajorImageVersion, MinorImageVersion;
    public ushort MajorSubsystemVersion, MinorSubsystemVersion;
    public uint Win32VersionValue;
    public uint SizeOfImage, SizeOfHeaders, CheckSum;
    public ushort Subsystem, DllCharacteristics;
    public ulong SizeOfStackReserve, SizeOfStackCommit;
    public ulong SizeOfHeapReserve, SizeOfHeapCommit;
    public uint LoaderFlags, NumberOfRvaAndSizes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public DataDirectory[] Dirs;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct SectionHeader
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name;
    public uint VirtualSize;
    public uint VirtualAddress;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint PointerToRelocations;
    public uint PointerToLinenumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public uint Characteristics;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct ExportDirectory
{
    public uint Characteristics, TimeDateStamp;
    public ushort MajorVersion, MinorVersion;
    public uint Name, Base;
    public uint NumberOfFunctions, NumberOfNames;
    public uint AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct ImportDescriptor
{
    public uint OriginalFirstThunk;
    public uint TimeDateStamp, ForwarderChain, Name, FirstThunk;
}

static class PeConsts
{
    public const ushort MZ_MAGIC = 0x5A4D;
    public const uint PE_SIG = 0x00004550;
    public const ushort MACHINE_I386 = 0x014C;
    public const ushort MACHINE_AMD64 = 0x8664;
    public const ushort MACHINE_IA64 = 0x0200;

    public const ushort FC_RELOCS_STRIPPED = 0x0001;
    public const ushort FC_EXECUTABLE_IMAGE = 0x0002;
    public const ushort FC_LINE_NUMS_STRIPPED = 0x0004;
    public const ushort FC_LOCAL_SYMS_STRIPPED = 0x0008;
    public const ushort FC_AGGRESIVE_WS_TRIM = 0x0010;
    public const ushort FC_LARGE_ADDRESS_AWARE = 0x0020;
    public const ushort FC_32BIT_MACHINE = 0x0100;
    public const ushort FC_DEBUG_STRIPPED = 0x0200;
    public const ushort FC_REMOVABLE_RUN_FROM_SWAP = 0x0400;
    public const ushort FC_NET_RUN_FROM_SWAP = 0x0800;
    public const ushort FC_SYSTEM = 0x1000;
    public const ushort FC_DLL = 0x2000;
    public const ushort FC_UP_SYSTEM_ONLY = 0x4000;
    public const ushort FC_BYTES_REVERSED_HI = 0x8000;

    public const ushort DLL_HIGH_ENTROPY_VA = 0x0020;
    public const ushort DLL_DYNAMIC_BASE = 0x0040;
    public const ushort DLL_FORCE_INTEGRITY = 0x0080;
    public const ushort DLL_NX_COMPAT = 0x0100;
    public const ushort DLL_NO_ISOLATION = 0x0200;
    public const ushort DLL_NO_SEH = 0x0400;
    public const ushort DLL_NO_BIND = 0x0800;
    public const ushort DLL_APPCONTAINER = 0x1000;
    public const ushort DLL_WDM_DRIVER = 0x2000;
    public const ushort DLL_GUARD_CF = 0x4000;
    public const ushort DLL_TERMINAL_SERVER_AWARE = 0x8000;

    public const uint SCN_MEM_EXECUTE = 0x20000000;
    public const uint SCN_MEM_READ = 0x40000000;
    public const uint SCN_MEM_WRITE = 0x80000000;

    public const uint ORDINAL_FLAG32 = 0x80000000;
    public const ulong ORDINAL_FLAG64 = 0x8000000000000000UL;
}

static class PeUtils
{
    public static uint RvaToOffset(uint rva, SectionHeader[] sections)
    {
        foreach (var s in sections)
        {
            uint va = s.VirtualAddress;
            uint vsz = s.VirtualSize;
            if (rva >= va && rva < va + vsz)
                return s.PointerToRawData + (rva - va);
        }
        return 0;
    }

    public static T Read<T>(byte[] buf, uint offset) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(buf, (int)offset, ptr, size);
            return Marshal.PtrToStructure<T>(ptr);
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static string ReadCString(byte[] buf, uint offset)
    {
        int end = (int)offset;
        while (end < buf.Length && buf[end] != 0) end++;
        return Encoding.ASCII.GetString(buf, (int)offset, end - (int)offset);
    }

    public static string TimestampToString(uint ts)
        => DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss");

    // собирает активные флаги в одну строку через пробел
    static string Flags<T>(T value, (T flag, string name)[] table) where T : struct
    {
        var parts = new System.Collections.Generic.List<string>();
        foreach (var (flag, name) in table)
        {
            // сравниваем через Convert, чтобы работало для ushort и uint
            ulong v = Convert.ToUInt64(value);
            ulong f = Convert.ToUInt64(flag);
            if ((v & f) != 0) parts.Add(name);
        }
        return parts.Count > 0 ? string.Join(" ", parts) : "—";
    }

    public static string FileCharacteristicsStr(ushort ch) => Flags(ch, new (ushort, string)[]
    {
        (PeConsts.FC_RELOCS_STRIPPED,         "RELOCS_STRIPPED"),
        (PeConsts.FC_EXECUTABLE_IMAGE,        "EXECUTABLE"),
        (PeConsts.FC_LINE_NUMS_STRIPPED,      "LINE_NUMS_STRIPPED"),
        (PeConsts.FC_LOCAL_SYMS_STRIPPED,     "LOCAL_SYMS_STRIPPED"),
        (PeConsts.FC_AGGRESIVE_WS_TRIM,       "AGGRESIVE_WS_TRIM"),
        (PeConsts.FC_LARGE_ADDRESS_AWARE,     "LARGE_ADDRESS_AWARE"),
        (PeConsts.FC_32BIT_MACHINE,           "32BIT"),
        (PeConsts.FC_DEBUG_STRIPPED,          "DEBUG_STRIPPED"),
        (PeConsts.FC_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP"),
        (PeConsts.FC_NET_RUN_FROM_SWAP,       "NET_RUN_FROM_SWAP"),
        (PeConsts.FC_SYSTEM,                  "SYSTEM"),
        (PeConsts.FC_DLL,                     "DLL"),
        (PeConsts.FC_UP_SYSTEM_ONLY,          "UP_SYSTEM_ONLY"),
        (PeConsts.FC_BYTES_REVERSED_HI,       "BYTES_REVERSED_HI"),
    });

    public static string DllCharacteristicsStr(ushort ch) => Flags(ch, new (ushort, string)[]
    {
        (PeConsts.DLL_HIGH_ENTROPY_VA,       "HIGH_ENTROPY_VA"),
        (PeConsts.DLL_DYNAMIC_BASE,          "DYNAMIC_BASE"),
        (PeConsts.DLL_FORCE_INTEGRITY,       "FORCE_INTEGRITY"),
        (PeConsts.DLL_NX_COMPAT,             "NX_COMPAT"),
        (PeConsts.DLL_NO_ISOLATION,          "NO_ISOLATION"),
        (PeConsts.DLL_NO_SEH,                "NO_SEH"),
        (PeConsts.DLL_NO_BIND,               "NO_BIND"),
        (PeConsts.DLL_APPCONTAINER,          "APPCONTAINER"),
        (PeConsts.DLL_WDM_DRIVER,            "WDM_DRIVER"),
        (PeConsts.DLL_GUARD_CF,              "GUARD_CF"),
        (PeConsts.DLL_TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE"),
    });

    public static string SectionRightsStr(uint ch)
    {
        string r = "";
        if ((ch & PeConsts.SCN_MEM_READ) != 0) r += "r";
        if ((ch & PeConsts.SCN_MEM_WRITE) != 0) r += "w";
        if ((ch & PeConsts.SCN_MEM_EXECUTE) != 0) r += "x";
        return r.Length > 0 ? r : "---";
    }

    // вывод строки «ключ : значение» с выравниванием
    public static void Row(string key, string value)
        => Console.WriteLine($"  {key,-24} {value}");
}

class Program
{
    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("usage: pe_parser <file1> [file2 ...]");
            return 1;
        }

        foreach (string filename in args)
            ParseFile(filename);

        return 0;
    }

    static void ParseFile(string filename)
    {
        byte[] buf;
        try { buf = File.ReadAllBytes(filename); }
        catch (Exception ex) { Console.WriteLine($"error: {ex.Message}"); return; }

        // DOS
        var dos = PeUtils.Read<DosHeader>(buf, 0);
        if (dos.e_magic != PeConsts.MZ_MAGIC)
        { Console.WriteLine($"{Path.GetFileName(filename)}: not a PE file"); return; }

        // NT signature
        uint ntBase = dos.e_lfanew;
        uint sig = BitConverter.ToUInt32(buf, (int)ntBase);
        if (sig != PeConsts.PE_SIG)
        { Console.WriteLine($"{Path.GetFileName(filename)}: invalid PE signature"); return; }

        // File Header
        uint fhOffset = ntBase + 4;
        var fh = PeUtils.Read<FileHeader>(buf, fhOffset);
        bool is64 = fh.Machine == PeConsts.MACHINE_AMD64 || fh.Machine == PeConsts.MACHINE_IA64;

        uint optBase = fhOffset + (uint)Marshal.SizeOf<FileHeader>();
        uint sectsOff = optBase + fh.SizeOfOptionalHeader;

        int numSects = fh.NumberOfSections;
        var sects = new SectionHeader[numSects];
        int sectSize = Marshal.SizeOf<SectionHeader>();
        for (int i = 0; i < numSects; i++)
            sects[i] = PeUtils.Read<SectionHeader>(buf, sectsOff + (uint)(i * sectSize));

        // ── file ─────────────────────────────────────────────────────────────
        Console.WriteLine($"\n{Path.GetFileName(filename)}");
        Console.WriteLine(new string('─', 48));

        string machineStr = fh.Machine switch
        {
            PeConsts.MACHINE_I386 => "x86",
            PeConsts.MACHINE_AMD64 => "x64",
            PeConsts.MACHINE_IA64 => "ia64",
            _ => $"0x{fh.Machine:X4}"
        };
        PeUtils.Row("arch", machineStr);
        PeUtils.Row("sections", fh.NumberOfSections.ToString());
        PeUtils.Row("timestamp", PeUtils.TimestampToString(fh.TimeDateStamp));
        PeUtils.Row("flags", $"0x{fh.Characteristics:X4}  {PeUtils.FileCharacteristicsStr(fh.Characteristics)}");

        // Optional Header
        ushort magic = 0;
        uint entryPoint = 0;
        ulong imageBase = 0;
        uint secAlign = 0;
        uint fileAlign = 0;
        uint sizeOfImage = 0;
        ushort dllChars = 0;

        uint expRva = 0, impRva = 0;
        uint resRva = 0, resSz = 0;
        uint relRva = 0, relSz = 0;

        if (!is64)
        {
            var opt = PeUtils.Read<OptionalHeader32>(buf, optBase);
            magic = opt.Magic; entryPoint = opt.AddressOfEntryPoint;
            imageBase = opt.ImageBase; secAlign = opt.SectionAlignment;
            fileAlign = opt.FileAlignment; sizeOfImage = opt.SizeOfImage;
            dllChars = opt.DllCharacteristics;
            if (opt.NumberOfRvaAndSizes > 0) expRva = opt.Dirs[0].VirtualAddress;
            if (opt.NumberOfRvaAndSizes > 1) impRva = opt.Dirs[1].VirtualAddress;
            if (opt.NumberOfRvaAndSizes > 2) { resRva = opt.Dirs[2].VirtualAddress; resSz = opt.Dirs[2].Size; }
            if (opt.NumberOfRvaAndSizes > 5) { relRva = opt.Dirs[5].VirtualAddress; relSz = opt.Dirs[5].Size; }
        }
        else
        {
            var opt = PeUtils.Read<OptionalHeader64>(buf, optBase);
            magic = opt.Magic; entryPoint = opt.AddressOfEntryPoint;
            imageBase = opt.ImageBase; secAlign = opt.SectionAlignment;
            fileAlign = opt.FileAlignment; sizeOfImage = opt.SizeOfImage;
            dllChars = opt.DllCharacteristics;
            if (opt.NumberOfRvaAndSizes > 0) expRva = opt.Dirs[0].VirtualAddress;
            if (opt.NumberOfRvaAndSizes > 1) impRva = opt.Dirs[1].VirtualAddress;
            if (opt.NumberOfRvaAndSizes > 2) { resRva = opt.Dirs[2].VirtualAddress; resSz = opt.Dirs[2].Size; }
            if (opt.NumberOfRvaAndSizes > 5) { relRva = opt.Dirs[5].VirtualAddress; relSz = opt.Dirs[5].Size; }
        }

        string magicStr = magic switch { 0x10B => "PE32", 0x20B => "PE32+", _ => "?" };
        PeUtils.Row("format", magicStr);
        PeUtils.Row("entry point", $"0x{entryPoint:X}");
        PeUtils.Row("image base", $"0x{imageBase:X}");
        PeUtils.Row("image size", $"0x{sizeOfImage:X}  ({sizeOfImage} bytes)");
        PeUtils.Row("section align", $"0x{secAlign:X}");
        PeUtils.Row("file align", $"0x{fileAlign:X}");
        PeUtils.Row("dll flags", $"0x{dllChars:X4}  {PeUtils.DllCharacteristicsStr(dllChars)}");

        // ── exports ──────────────────────────────────────────────────────────
        Console.WriteLine("\nexports");
        Console.WriteLine(new string('─', 48));

        if (expRva == 0)
        {
            Console.WriteLine("  none");
        }
        else
        {
            uint expOff = PeUtils.RvaToOffset(expRva, sects);
            if (expOff == 0) { Console.WriteLine("  (section not found)"); }
            else
            {
                var expDir = PeUtils.Read<ExportDirectory>(buf, expOff);
                uint dllNameOff = PeUtils.RvaToOffset(expDir.Name, sects);
                PeUtils.Row("dll name", PeUtils.ReadCString(buf, dllNameOff));
                PeUtils.Row("functions", expDir.NumberOfFunctions.ToString());
                PeUtils.Row("names", expDir.NumberOfNames.ToString());
                PeUtils.Row("base", expDir.Base.ToString());
                Console.WriteLine();

                uint nameArrOff = PeUtils.RvaToOffset(expDir.AddressOfNames, sects);
                uint ordArrOff = PeUtils.RvaToOffset(expDir.AddressOfNameOrdinals, sects);
                uint funcArrOff = PeUtils.RvaToOffset(expDir.AddressOfFunctions, sects);

                for (uint i = 0; i < expDir.NumberOfNames; i++)
                {
                    uint nameRva = BitConverter.ToUInt32(buf, (int)(nameArrOff + i * 4));
                    ushort ord = BitConverter.ToUInt16(buf, (int)(ordArrOff + i * 2));
                    uint funcRva = (ord < expDir.NumberOfFunctions)
                                        ? BitConverter.ToUInt32(buf, (int)(funcArrOff + ord * 4)) : 0;
                    uint nameOff = PeUtils.RvaToOffset(nameRva, sects);
                    Console.WriteLine($"  #{expDir.Base + ord,-6} 0x{funcRva:X8}  {PeUtils.ReadCString(buf, nameOff)}");
                }
            }
        }

        // ── imports ──────────────────────────────────────────────────────────
        Console.WriteLine("\nimports");
        Console.WriteLine(new string('─', 48));

        if (impRva == 0)
        {
            Console.WriteLine("  none");
        }
        else
        {
            uint impOff = PeUtils.RvaToOffset(impRva, sects);
            if (impOff == 0) { Console.WriteLine("  (section not found)"); }
            else
            {
                int impSize = Marshal.SizeOf<ImportDescriptor>();
                uint cur = impOff;

                while (true)
                {
                    var imp = PeUtils.Read<ImportDescriptor>(buf, cur);
                    if (imp.Name == 0) break;

                    uint dllNameOff = PeUtils.RvaToOffset(imp.Name, sects);
                    Console.WriteLine($"\n  {PeUtils.ReadCString(buf, dllNameOff)}");

                    uint thunkRva = imp.OriginalFirstThunk != 0 ? imp.OriginalFirstThunk : imp.FirstThunk;
                    uint thunkOff = PeUtils.RvaToOffset(thunkRva, sects);

                    if (thunkOff != 0)
                    {
                        if (!is64)
                        {
                            uint pos = thunkOff;
                            while (true)
                            {
                                uint thunk = BitConverter.ToUInt32(buf, (int)pos);
                                if (thunk == 0) break;
                                if ((thunk & PeConsts.ORDINAL_FLAG32) != 0)
                                    Console.WriteLine($"    ord {thunk & 0xFFFF}");
                                else
                                    Console.WriteLine($"    {PeUtils.ReadCString(buf, PeUtils.RvaToOffset(thunk, sects) + 2)}");
                                pos += 4;
                            }
                        }
                        else
                        {
                            uint pos = thunkOff;
                            while (true)
                            {
                                ulong thunk = BitConverter.ToUInt64(buf, (int)pos);
                                if (thunk == 0) break;
                                if ((thunk & PeConsts.ORDINAL_FLAG64) != 0)
                                    Console.WriteLine($"    ord {thunk & 0xFFFF}");
                                else
                                    Console.WriteLine($"    {PeUtils.ReadCString(buf, PeUtils.RvaToOffset((uint)thunk, sects) + 2)}");
                                pos += 8;
                            }
                        }
                    }
                    cur += (uint)impSize;
                }
            }
        }

        // ── sections ─────────────────────────────────────────────────────────
        Console.WriteLine("\nsections");
        Console.WriteLine(new string('─', 48));
        Console.WriteLine($"  {"name",-10} {"vaddr",10} {"vsize",8} {"rawsize",8}  perm");
        Console.WriteLine($"  {new string('-', 44)}");
        for (int i = 0; i < numSects; i++)
        {
            string sname = Encoding.ASCII.GetString(sects[i].Name).TrimEnd('\0');
            string perm = PeUtils.SectionRightsStr(sects[i].Characteristics);
            Console.WriteLine($"  {sname,-10} {$"0x{sects[i].VirtualAddress:X}",10} {$"0x{sects[i].VirtualSize:X}",8} {$"0x{sects[i].SizeOfRawData:X}",8}  {perm}");
        }

        // ── misc ─────────────────────────────────────────────────────────────
        Console.WriteLine("\nmisc");
        Console.WriteLine(new string('─', 48));
        PeUtils.Row("relocations", relRva != 0 && relSz != 0 ? $"0x{relRva:X}  size 0x{relSz:X}" : "none");
        PeUtils.Row("resources", resRva != 0 && resSz != 0 ? $"0x{resRva:X}  size 0x{resSz:X}" : "none");

        Console.WriteLine();
    }
}
