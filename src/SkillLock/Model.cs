namespace SkillLock;

public enum Severity { Info = 0, Warning = 1, Error = 2 }

public enum SkillOrigin { Package, Repository }

/// <summary>A skill folder: <c>SKILL.md</c> plus every file next to it.</summary>
public sealed class Skill
{
    /// <summary>Stable identity used in the lock file, e.g. <c>nuget:markout/markout</c> or <c>repo:.agents/skills/review</c>.</summary>
    public required string Key { get; init; }

    /// <summary>The folder name (and the expected <c>name</c> in the frontmatter).</summary>
    public required string FolderName { get; init; }

    public required SkillOrigin Origin { get; init; }

    /// <summary>Absolute path of the skill folder.</summary>
    public required string Directory { get; init; }

    /// <summary>Files of the skill, relative to <see cref="Directory"/>, with forward slashes. Always contains <c>SKILL.md</c>.</summary>
    public required IReadOnlyList<string> Files { get; init; }

    public string? PackageId { get; init; }
    public string? PackageVersion { get; init; }
    public bool IsDirectDependency { get; init; }

    /// <summary>Projects (relative to the root) that bring this skill in through their packages.</summary>
    public List<string> Projects { get; } = [];

    /// <summary>The skill's declared name, once the frontmatter is parsed.</summary>
    public string? DeclaredName { get; set; }

    public string SkillFilePath => Path.Combine(Directory, Files.First(f => f.Equals("SKILL.md", StringComparison.OrdinalIgnoreCase)));

    /// <summary>Where the skill comes from, for people: <c>Markout 0.40.0</c> or <c>.agents/skills/review</c>.</summary>
    public string SourceDisplay => Origin == SkillOrigin.Package
        ? $"{PackageId} {PackageVersion}{(IsDirectDependency ? "" : " (transitive)")}"
        : Key["repo:".Length..];

    /// <summary>The display path of a file in the skill: <c>Markout 0.40.0 › skills/markout/SKILL.md</c>.</summary>
    public string DisplayPath(string file) => Origin == SkillOrigin.Package
        ? $"{PackageId} {PackageVersion} › skills/{FolderName}/{file}"
        : $"{Key["repo:".Length..]}/{file}";
}

public sealed record Finding(
    Rule Rule,
    Severity Severity,
    string Message,
    Skill? Skill,
    string? File,
    int Line,
    int Column,
    string? Evidence)
{
    /// <summary>Stable across line moves: rule, file and the matched text.</summary>
    public string Fingerprint { get; init; } = "";

    /// <summary>True when the lock file records this finding as reviewed and accepted.</summary>
    public bool Accepted { get; set; }

    public string? AbsolutePath => Skill is null || File is null ? null : Path.Combine(Skill.Directory, File.Replace('/', Path.DirectorySeparatorChar));
}

public enum LockState { Unlocked, Locked, New, Changed, Removed }

public sealed record SkillStatus(Skill? Skill, string Key, LockState State, IReadOnlyList<string> ChangedFiles);
