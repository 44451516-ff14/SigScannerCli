using System.Text.RegularExpressions;
using Iced.Intel;

namespace BossMod.SigScannerCli;

internal static partial class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        try
        {
            var options = Options.Parse(args);
            var signatures = options.SourceDirectory is { Length: > 0 }
                ? SignatureSource.Extract(options.SourceDirectory)
                : options.Signature is { Length: > 0 }
                    ? [new SignatureEntry("<command-line>", 0, "ScanText", options.Signature)]
                    : KnownSignatures.All.ToList();

            if (signatures.Count == 0)
            {
                Console.Error.WriteLine($"No SigScanner signatures found under {options.SourceDirectory}.");
                return 1;
            }

            var foundAnyMissing = ScanFile(options, signatures);
            return foundAnyMissing ? 2 : 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static bool ScanFile(Options options, List<SignatureEntry> signatures)
    {
        var image = PeImage.Load(options.FilePath!);
        var foundAnyMissing = false;
        var matchedSignatures = 0;
        var consistentSignatures = 0;
        var changedSignatures = 0;
        var missing = new List<SignatureEntry>();
        foreach (var entry in signatures)
        {
            var pattern = SignaturePattern.Parse(entry.Signature);
            var matches = image.Scan(pattern, options.All);

            if (matches.Count == 0)
            {
                foundAnyMissing = true;
                missing.Add(entry);
                WriteColored(ConsoleColor.Red, $"MISSING {entry.Method,-19} {entry.Location}  expected {FormatExpected(entry)}");
                continue;
            }

            ++matchedSignatures;
            foreach (var match in matches)
            {
                var hasAnalysis = TryAnalyzeFunction(image, entry, pattern, match, out var analysis);
                var actual = hasAnalysis ? FormatAnalysis(analysis) : "func-linear-len~=n/a args~=n/a";

                if (entry.ExpectedLinearLength is { } expectedLength && entry.ExpectedRegisterArgumentCount is { } expectedArgs)
                {
                    if (hasAnalysis && analysis.LinearLength == expectedLength && analysis.EstimatedRegisterArgumentCount == expectedArgs)
                    {
                        ++consistentSignatures;
                        WriteColored(ConsoleColor.Green, $"OK      {entry.Method,-19} {entry.Location}  {actual}");
                    }
                    else
                    {
                        foundAnyMissing = true;
                        ++changedSignatures;
                        WriteColored(ConsoleColor.Yellow, $"CHANGED {entry.Method,-19} {entry.Location}  expected {FormatExpected(entry)}  actual {actual}");
                    }
                }
                else
                {
                    WriteColored(ConsoleColor.Green, $"FOUND   {entry.Method,-19} {entry.Location}  {actual}");
                }

                if (!options.All && entry.Method != "ScanAllText")
                {
                    break;
                }
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Summary: {matchedSignatures}/{signatures.Count} signatures found, {consistentSignatures} consistent, {changedSignatures} changed, {missing.Count} missing.");
        if (missing.Count > 0)
        {
            WriteColored(ConsoleColor.Red, "Missing signatures:");
            foreach (var entry in missing)
            {
                Console.WriteLine($"  - {entry.Method} {entry.Location}  expected {FormatExpected(entry)}");
            }
        }

        return foundAnyMissing;
    }

    private static string FormatAnalysis(FunctionAnalysis analysis) => $"func-linear-len~=0x{analysis.LinearLength:X} ({analysis.LinearLength}) args~<={analysis.EstimatedRegisterArgumentCount}";

    private static string FormatExpected(SignatureEntry entry)
    {
        if (entry.ExpectedLinearLength is { } length && entry.ExpectedRegisterArgumentCount is { } args)
        {
            return $"func-linear-len~=0x{length:X} ({length}) args~<={args}";
        }

        return "func-linear-len~=n/a args~=n/a";
    }

    private static void WriteColored(ConsoleColor color, string text)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = previous;
    }

    private static bool TryResolveRelativeTarget(SignaturePattern pattern, PeMatch match, out ulong target)
    {
        target = 0;

        if (pattern.Bytes.Length < 5 || pattern.Bytes[0] is not (0xE8 or 0xE9))
        {
            return false;
        }

        var displacement = BitConverter.ToInt32(match.Bytes.AsSpan(1, 4));
        target = (ulong)((long)match.VirtualAddress + 5 + displacement);
        return true;
    }

    private static bool TryResolveStaticAddress(SignaturePattern pattern, PeMatch match, out ulong target)
    {
        target = 0;

        var displacementOffset = pattern.FirstWildcardRun(4);
        if (displacementOffset < 0)
        {
            return false;
        }

        var displacement = BitConverter.ToInt32(match.Bytes.AsSpan(displacementOffset, 4));
        target = (ulong)((long)match.VirtualAddress + displacementOffset + 4 + displacement);
        return true;
    }

    private static bool TryAnalyzeFunction(PeImage image, SignatureEntry entry, SignaturePattern pattern, PeMatch match, out FunctionAnalysis analysis)
    {
        analysis = default;
        if (TryResolveRelativeTarget(pattern, match, out var target))
        {
            return FunctionAnalyzer.TryAnalyze(image, target, out analysis);
        }

        if (entry.Method is "HookFromSignature" or "HookAddress")
        {
            return FunctionAnalyzer.TryAnalyze(image, match.VirtualAddress, out analysis);
        }

        return false;
    }

}

internal sealed record Options(string FilePath, string? Signature, string? SourceDirectory, bool All)
{
    public static Options Parse(string[] args)
    {
        string? filePath = null;
        string? signature = null;
        string? sourceDirectory = null;
        var all = false;

        for (var i = 0; i < args.Length; ++i)
        {
            switch (args[i])
            {
                case "--all":
                    all = true;
                    break;
                case "--file":
                    filePath = RequireValue(args, ref i);
                    break;
                case "--sig":
                    signature = RequireValue(args, ref i);
                    break;
                case "--source":
                    sourceDirectory = RequireValue(args, ref i);
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        if (!string.IsNullOrWhiteSpace(signature) && !string.IsNullOrWhiteSpace(sourceDirectory))
        {
            throw new ArgumentException("Specify only one of --sig or --source.");
        }

        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Missing required --file.");
        }

        return new(filePath ?? "", signature, sourceDirectory, all);
    }

    private static string RequireValue(string[] args, ref int index)
    {
        if (++index >= args.Length || args[index].StartsWith('-'))
        {
            throw new ArgumentException($"Missing value for {args[index - 1]}.");
        }

        return args[index];
    }
}

internal sealed record SignatureEntry(string File, int Line, string Method, string Signature, int? ExpectedLinearLength = null, int? ExpectedRegisterArgumentCount = null)
{
    public string Location
    {
        get
        {
            var file = File;
            if (Path.IsPathFullyQualified(file))
            {
                file = Path.GetRelativePath(Environment.CurrentDirectory, file);
            }

            return Line > 0 ? $"{file}:{Line}" : file;
        }
    }
}

internal static partial class SignatureSource
{
    public static List<SignatureEntry> Extract(string sourceDirectory)
    {
        if (!Directory.Exists(sourceDirectory))
        {
            throw new DirectoryNotFoundException(sourceDirectory);
        }

        var entries = new List<SignatureEntry>();
        foreach (var file in Directory.EnumerateFiles(sourceDirectory, "*.cs", SearchOption.AllDirectories))
        {
            var lineNumber = 0;
            foreach (var line in File.ReadLines(file))
            {
                ++lineNumber;
                var scanLine = StripLineComment(line);
                foreach (Match match in SigScannerCallRegex().Matches(scanLine))
                {
                    entries.Add(new(file, lineNumber, match.Groups["method"].Value, Regex.Unescape(match.Groups["sig"].Value)));
                }
                foreach (Match match in HookFromSignatureRegex().Matches(scanLine))
                {
                    entries.Add(new(file, lineNumber, "HookFromSignature", Regex.Unescape(match.Groups["sig"].Value)));
                }
                foreach (Match match in HookAddressRegex().Matches(scanLine))
                {
                    entries.Add(new(file, lineNumber, "HookAddress", Regex.Unescape(match.Groups["sig"].Value)));
                }
            }
        }

        return entries;
    }

    [GeneratedRegex("SigScanner\\.(?<method>ScanText|TryScanText|ScanAllText|GetStaticAddressFromSig)\\(\"(?<sig>[^\"]+)")]
    private static partial Regex SigScannerCallRegex();

    [GeneratedRegex("HookFromSignature(?:<[^>]+>)?\\(\"(?<sig>[^\"]+)")]
    private static partial Regex HookFromSignatureRegex();

    [GeneratedRegex("\\bnew\\(\"(?<sig>(?:[0-9A-F?]{2}|\\?)(?:\\s+(?:[0-9A-F?]{2}|\\?))+)\"")]
    private static partial Regex HookAddressRegex();

    private static string StripLineComment(string line)
    {
        var stringLiteral = false;
        for (var i = 0; i < line.Length - 1; ++i)
        {
            if (line[i] == '"' && (i == 0 || line[i - 1] != '\\'))
            {
                stringLiteral = !stringLiteral;
            }

            if (!stringLiteral && line[i] == '/' && line[i + 1] == '/')
            {
                return line[..i];
            }
        }

        return line;
    }
}

internal sealed class SignaturePattern
{
    public required byte[] Bytes { get; init; }
    public required bool[] Wildcards { get; init; }

    public static SignaturePattern Parse(string signature)
    {
        var tokens = signature.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
        {
            throw new ArgumentException("Signature is empty.");
        }

        var bytes = new byte[tokens.Length];
        var wildcards = new bool[tokens.Length];

        for (var i = 0; i < tokens.Length; ++i)
        {
            if (tokens[i] is "?" or "??")
            {
                wildcards[i] = true;
                continue;
            }

            if (tokens[i].Length != 2 || !byte.TryParse(tokens[i], System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
            {
                throw new ArgumentException($"Invalid signature token '{tokens[i]}'.");
            }
        }

        return new() { Bytes = bytes, Wildcards = wildcards };
    }

    public int FirstWildcardRun(int length)
    {
        for (var i = 0; i <= Wildcards.Length - length; ++i)
        {
            var ok = true;
            for (var j = 0; j < length; ++j)
            {
                ok &= Wildcards[i + j];
            }

            if (ok)
            {
                return i;
            }
        }

        return -1;
    }

    public bool Matches(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < Bytes.Length; ++i)
        {
            if (!Wildcards[i] && data[i] != Bytes[i])
            {
                return false;
            }
        }

        return true;
    }
}

internal sealed class PeImage
{
    private readonly byte[] _bytes;

    private PeImage(string path, byte[] bytes, ulong imageBase, List<PeSection> sections)
    {
        Path = path;
        _bytes = bytes;
        ImageBase = imageBase;
        Sections = sections;
    }

    public string Path { get; }
    public ulong ImageBase { get; }
    public List<PeSection> Sections { get; }

    public static PeImage Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("PE file was not found.", path);
        }

        var bytes = File.ReadAllBytes(path);
        if (bytes.Length < 0x40 || ReadUInt16(bytes, 0) != 0x5A4D)
        {
            throw new InvalidDataException("File is not a valid MZ executable.");
        }

        var peOffset = ReadInt32(bytes, 0x3C);
        if (peOffset < 0 || peOffset + 0x18 >= bytes.Length || ReadUInt32(bytes, peOffset) != 0x00004550)
        {
            throw new InvalidDataException("File is not a valid PE executable.");
        }

        var numberOfSections = ReadUInt16(bytes, peOffset + 6);
        var optionalHeaderSize = ReadUInt16(bytes, peOffset + 20);
        var optionalHeaderOffset = peOffset + 24;
        var magic = ReadUInt16(bytes, optionalHeaderOffset);
        var imageBase = magic switch
        {
            0x20B => ReadUInt64(bytes, optionalHeaderOffset + 24),
            0x10B => ReadUInt32(bytes, optionalHeaderOffset + 28),
            _ => throw new InvalidDataException($"Unsupported PE optional header magic: 0x{magic:X}.")
        };

        var sectionOffset = optionalHeaderOffset + optionalHeaderSize;
        var sections = new List<PeSection>();
        for (var i = 0; i < numberOfSections; ++i)
        {
            var offset = sectionOffset + i * 40;
            if (offset + 40 > bytes.Length)
            {
                throw new InvalidDataException("PE section table is truncated.");
            }

            var nameBytes = bytes.AsSpan(offset, 8);
            var nameLength = nameBytes.IndexOf((byte)0);
            var name = System.Text.Encoding.ASCII.GetString(nameLength >= 0 ? nameBytes[..nameLength] : nameBytes);
            var virtualSize = ReadUInt32(bytes, offset + 8);
            var virtualAddress = ReadUInt32(bytes, offset + 12);
            var rawSize = ReadUInt32(bytes, offset + 16);
            var rawPointer = ReadUInt32(bytes, offset + 20);
            var characteristics = ReadUInt32(bytes, offset + 36);

            if (rawSize == 0 || rawPointer >= bytes.Length)
            {
                continue;
            }

            var availableRawSize = Math.Min(rawSize, (uint)(bytes.Length - rawPointer));
            sections.Add(new(name, virtualAddress, virtualSize, rawPointer, availableRawSize, characteristics));
        }

        return new(System.IO.Path.GetFullPath(path), bytes, imageBase, sections);
    }

    public List<PeMatch> Scan(SignaturePattern pattern, bool all)
    {
        var matches = new List<PeMatch>();

        foreach (var section in Sections.Where(s => s.IsExecutable || s.Name == ".text"))
        {
            var data = _bytes.AsSpan((int)section.RawPointer, (int)section.RawSize);
            for (var i = 0; i <= data.Length - pattern.Bytes.Length; ++i)
            {
                if (!pattern.Matches(data.Slice(i, pattern.Bytes.Length)))
                {
                    continue;
                }

                var fileOffset = section.RawPointer + (uint)i;
                var rva = section.VirtualAddress + (uint)i;
                var va = ImageBase + rva;
                matches.Add(new(fileOffset, rva, va, data.Slice(i, pattern.Bytes.Length).ToArray()));
                if (!all)
                {
                    return matches;
                }
            }
        }

        return matches;
    }

    public bool TryReadVirtual(ulong virtualAddress, int maxSize, out byte[] bytes)
    {
        bytes = [];
        if (virtualAddress < ImageBase)
        {
            return false;
        }

        var rva = virtualAddress - ImageBase;
        var section = Sections.FirstOrDefault(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + s.RawSize);
        if (section is null)
        {
            return false;
        }

        var offsetInSection = (uint)(rva - section.VirtualAddress);
        var fileOffset = section.RawPointer + offsetInSection;
        var available = (int)Math.Min(section.RawSize - offsetInSection, (uint)maxSize);
        if (available <= 0 || fileOffset >= _bytes.Length)
        {
            return false;
        }

        available = Math.Min(available, _bytes.Length - (int)fileOffset);
        bytes = _bytes.AsSpan((int)fileOffset, available).ToArray();
        return true;
    }

    private static ushort ReadUInt16(byte[] bytes, int offset) => BitConverter.ToUInt16(bytes, offset);
    private static int ReadInt32(byte[] bytes, int offset) => BitConverter.ToInt32(bytes, offset);
    private static uint ReadUInt32(byte[] bytes, int offset) => BitConverter.ToUInt32(bytes, offset);
    private static ulong ReadUInt64(byte[] bytes, int offset) => BitConverter.ToUInt64(bytes, offset);
}

internal sealed record PeSection(string Name, uint VirtualAddress, uint VirtualSize, uint RawPointer, uint RawSize, uint Characteristics)
{
    private const uint ImageScnMemExecute = 0x20000000;
    public bool IsExecutable => (Characteristics & ImageScnMemExecute) != 0;
}

internal sealed record PeMatch(uint FileOffset, uint Rva, ulong VirtualAddress, byte[] Bytes);

internal readonly record struct FunctionAnalysis(int LinearLength, int EstimatedRegisterArgumentCount);

internal static class FunctionAnalyzer
{
    private const int MaxFunctionBytes = 4096;
    private const int MaxArgumentProbeBytes = 128;

    public static bool TryAnalyze(PeImage image, ulong functionVa, out FunctionAnalysis analysis)
    {
        analysis = default;
        if (!image.TryReadVirtual(functionVa, MaxFunctionBytes, out var bytes) || bytes.Length == 0)
        {
            return false;
        }

        var decoder = Decoder.Create(64, new ByteArrayCodeReader(bytes));
        decoder.IP = functionVa;

        var length = 0;
        var estimatedArgs = new HashSet<Register>();
        var overwritten = new HashSet<Register>();

        while (decoder.IP - functionVa < (ulong)bytes.Length)
        {
            decoder.Decode(out var instruction);
            if (instruction.IsInvalid)
            {
                break;
            }

            length = checked((int)(instruction.NextIP - functionVa));
            ProbeArgumentRegisters(instruction, length, estimatedArgs, overwritten);

            if (instruction.FlowControl is FlowControl.Return or FlowControl.UnconditionalBranch)
            {
                break;
            }
        }

        analysis = new(length, estimatedArgs.Count);
        return length > 0;
    }

    private static void ProbeArgumentRegisters(Instruction instruction, int currentLength, HashSet<Register> estimatedArgs, HashSet<Register> overwritten)
    {
        if (currentLength > MaxArgumentProbeBytes || instruction.FlowControl != FlowControl.Next)
        {
            return;
        }

        var destination = GetWrittenRegister(instruction);
        for (var i = 0; i < instruction.OpCount; ++i)
        {
            var register = instruction.GetOpKind(i) == OpKind.Register ? Normalize(instruction.GetOpRegister(i)) : Register.None;
            if (IsArgumentRegister(register) && register != destination && !overwritten.Contains(register))
            {
                estimatedArgs.Add(register);
            }
        }

        AddMemoryArgumentRegister(instruction.MemoryBase, estimatedArgs, overwritten);
        AddMemoryArgumentRegister(instruction.MemoryIndex, estimatedArgs, overwritten);

        if (IsArgumentRegister(destination))
        {
            overwritten.Add(destination);
        }
    }

    private static Register GetWrittenRegister(Instruction instruction)
    {
        if (instruction.OpCount == 0 || instruction.GetOpKind(0) != OpKind.Register)
        {
            return Register.None;
        }

        var destination = Normalize(instruction.GetOpRegister(0));
        return instruction.Mnemonic switch
        {
            Mnemonic.Mov or Mnemonic.Movzx or Mnemonic.Movsxd or Mnemonic.Lea or Mnemonic.Xor or Mnemonic.Sub when IsArgumentRegister(destination) => destination,
            _ => Register.None
        };
    }

    private static void AddMemoryArgumentRegister(Register register, HashSet<Register> estimatedArgs, HashSet<Register> overwritten)
    {
        register = Normalize(register);
        if (IsArgumentRegister(register) && !overwritten.Contains(register))
        {
            estimatedArgs.Add(register);
        }
    }

    private static bool IsArgumentRegister(Register register) => register is Register.RCX or Register.RDX or Register.R8 or Register.R9;

    private static Register Normalize(Register register) => register switch
    {
        Register.CL or Register.CX or Register.ECX or Register.RCX => Register.RCX,
        Register.DL or Register.DX or Register.EDX or Register.RDX => Register.RDX,
        Register.R8L or Register.R8W or Register.R8D or Register.R8 => Register.R8,
        Register.R9L or Register.R9W or Register.R9D or Register.R9 => Register.R9,
        _ => register
    };
}
