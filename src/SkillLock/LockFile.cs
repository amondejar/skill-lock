using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkillLock;

/// <summary><c>skills.lock.json</c>: the reviewed version of every skill, by hash, plus the findings someone accepted.</summary>
public sealed class LockFile
{
    public const string FileName = "skills.lock.json";
    public const int CurrentVersion = 1;

    [JsonPropertyName("version")] public int Version { get; set; } = CurrentVersion;
    [JsonPropertyName("skills")] public SortedDictionary<string, LockedSkill> Skills { get; set; } = new(StringComparer.Ordinal);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static LockFile Load(string path)
    {
        try
        {
            var lockFile = JsonSerializer.Deserialize<LockFile>(File.ReadAllText(path), Json) ?? new LockFile();
            if (lockFile.Version > CurrentVersion)
                throw new SkillLockException($"{path} was written by a newer SkillLock (format {lockFile.Version}); update the tool.");
            return lockFile;
        }
        catch (JsonException e)
        {
            throw new SkillLockException($"{path} is not a valid lock file: {e.Message}");
        }
    }

    public void Save(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(this, Json).Replace("\r\n", "\n") + "\n", new UTF8Encoding(false));

    /// <summary>Looks for skills.lock.json in the directory and its parents, stopping at the repository root.</summary>
    public static string? Find(string startDirectory)
    {
        for (var directory = new DirectoryInfo(startDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, FileName);
            if (File.Exists(candidate)) return candidate;
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, ".git"))) return null;
        }
        return null;
    }

    /// <summary>Where a new lock file goes: the repository root if there is one, else the start directory.</summary>
    public static string DefaultPath(string startDirectory)
    {
        for (var directory = new DirectoryInfo(startDirectory); directory is not null; directory = directory.Parent)
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, ".git")))
                return Path.Combine(directory.FullName, FileName);
        return Path.Combine(startDirectory, FileName);
    }
}

public sealed class LockedSkill
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("source")] public string? Source { get; set; }
    [JsonPropertyName("sha256")] public string Sha256 { get; set; } = "";
    [JsonPropertyName("files")] public SortedDictionary<string, string> Files { get; set; } = new(StringComparer.Ordinal);
    [JsonPropertyName("accepted")] public List<AcceptedFinding>? Accepted { get; set; }
}

public sealed class AcceptedFinding
{
    [JsonPropertyName("rule")] public string Rule { get; set; } = "";
    [JsonPropertyName("fingerprint")] public string Fingerprint { get; set; } = "";
    [JsonPropertyName("file")] public string? File { get; set; }
    [JsonPropertyName("evidence")] public string? Evidence { get; set; }
}

public static class SkillHasher
{
    /// <summary>Hash of each file. Line endings are normalized so a checkout with autocrlf hashes like CI.</summary>
    public static SortedDictionary<string, string> HashFiles(Skill skill)
    {
        var hashes = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in skill.Files)
        {
            var path = Path.Combine(skill.Directory, file.Replace('/', Path.DirectorySeparatorChar));
            byte[] bytes;
            try { bytes = File.ReadAllBytes(path); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { bytes = Encoding.UTF8.GetBytes($"<unreadable:{e.GetType().Name}>"); }
            hashes[file] = Hex(SHA256.HashData(Normalize(bytes)));
        }
        return hashes;
    }

    public static string Combine(SortedDictionary<string, string> files)
    {
        var builder = new StringBuilder();
        foreach (var (file, hash) in files) builder.Append(file).Append('\0').Append(hash).Append('\n');
        return Hex(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    private static byte[] Normalize(byte[] bytes)
    {
        if (Array.IndexOf(bytes, (byte)0) >= 0) return bytes; // binary: as is
        var result = new List<byte>(bytes.Length);
        for (var i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == '\r' && i + 1 < bytes.Length && bytes[i + 1] == '\n') continue;
            result.Add(bytes[i]);
        }
        return [.. result];
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
