using System.Text.Json;
using System.Text.RegularExpressions;

namespace SkillLock;

/// <summary>What to audit: the root (for the lock file and repository skills) and the assets files of the projects.</summary>
public sealed record AuditTarget(string Root, IReadOnlyList<string> AssetsFiles, bool IncludeRepositorySkills)
{
    /// <summary>Where the repository skill folders are (default: <see cref="Root"/>).</summary>
    public string? RepositoryRoot { get; init; }

    /// <summary>
    /// Build mode: repository skills are read only to detect packages that shadow them; their own findings
    /// belong to the repository-wide check, not to every project build.
    /// </summary>
    public bool PackageFindingsOnly { get; init; }

    /// <summary>The repository root: the nearest folder with .git, or the start folder.</summary>
    public static string FindRepositoryRoot(string start)
    {
        for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, ".git")))
                return directory.FullName;
        return start;
    }

    /// <summary>
    /// Resolves a path given on the command line: a directory (every project.assets.json under it, plus the repository skill folders),
    /// a project file (its obj/project.assets.json) or a solution (the assets files of its projects).
    /// </summary>
    public static AuditTarget Resolve(string path, IReadOnlyList<string>? explicitAssets = null, bool? includeRepositorySkills = null)
    {
        path = Path.GetFullPath(path);
        if (explicitAssets is { Count: > 0 })
        {
            var root = Directory.Exists(path) ? path : Path.GetDirectoryName(path)!;
            return new(root, explicitAssets.Select(Path.GetFullPath).ToList(), includeRepositorySkills ?? false);
        }

        if (Directory.Exists(path))
            return new(path, FindAssetsFiles(path), includeRepositorySkills ?? true);

        if (!File.Exists(path)) throw new SkillLockException($"Path not found: {path}");

        var directory = Path.GetDirectoryName(path)!;
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is ".sln" or ".slnx")
        {
            var assets = SolutionProjects(path)
                .Select(p => Path.Combine(Path.GetDirectoryName(p)!, "obj", "project.assets.json"))
                .Where(File.Exists)
                .ToList();
            return new(directory, assets, includeRepositorySkills ?? true);
        }

        if (extension.EndsWith("proj", StringComparison.Ordinal))
        {
            var assets = Path.Combine(directory, "obj", "project.assets.json");
            return new(directory, File.Exists(assets) ? [assets] : [], includeRepositorySkills ?? false);
        }

        if (Path.GetFileName(path).Equals("project.assets.json", StringComparison.OrdinalIgnoreCase))
            return new(directory, [path], includeRepositorySkills ?? false);

        throw new SkillLockException($"Expected a directory, a project, a solution or a project.assets.json file: {path}");
    }

    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase) { ".git", "node_modules", ".vs", ".idea", "bin", "packages" };

    private static List<string> FindAssetsFiles(string root)
    {
        var found = new List<string>();
        var pending = new Stack<string>([root]);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> children;
            try { children = Directory.EnumerateDirectories(directory); }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException) { continue; }

            foreach (var child in children)
            {
                if (SkippedDirectories.Contains(Path.GetFileName(child))) continue;
                var assets = Path.Combine(child, "project.assets.json");
                if (File.Exists(assets)) found.Add(assets);
                pending.Push(child);
            }
        }
        found.Sort(StringComparer.Ordinal);
        return found;
    }

    private static readonly Regex SlnProject = new(@"^Project\([^)]*\)\s*=\s*""[^""]*""\s*,\s*""([^""]+\.\w*proj)""", RegexOptions.Multiline);
    private static readonly Regex SlnxProject = new(@"<Project\s+[^>]*Path\s*=\s*""([^""]+)""", RegexOptions.IgnoreCase);

    private static IEnumerable<string> SolutionProjects(string solution)
    {
        var text = File.ReadAllText(solution);
        var regex = solution.EndsWith(".slnx", StringComparison.OrdinalIgnoreCase) ? SlnxProject : SlnProject;
        var directory = Path.GetDirectoryName(solution)!;
        foreach (Match match in regex.Matches(text))
            yield return Path.GetFullPath(Path.Combine(directory, match.Groups[1].Value.Replace('\\', Path.DirectorySeparatorChar)));
    }
}

public sealed class SkillLockException(string message) : Exception(message);

/// <summary>Finds the skills a target brings in.</summary>
public static class SkillDiscovery
{
    /// <summary>Folders where agents look for project skills (and where dotnet-package-skills copies package skills).</summary>
    public static readonly string[] RepositorySkillFolders = [".agents/skills", ".claude/skills", ".github/skills"];

    private static readonly Regex PackageSkillFile = new(@"^skills/([^/]+)/SKILL\.md$", RegexOptions.IgnoreCase);

    public static DiscoveryResult Discover(AuditTarget target)
    {
        var result = new DiscoveryResult();
        var byKey = new Dictionary<string, Skill>(StringComparer.Ordinal);

        foreach (var assets in target.AssetsFiles)
        {
            try { ReadAssets(target.Root, assets, byKey, result); }
            catch (JsonException e) { result.Problems.Add($"Could not read {assets}: {e.Message}"); }
        }

        if (target.IncludeRepositorySkills)
        {
            foreach (var folder in RepositorySkillFolders)
            {
                var directory = Path.Combine(target.RepositoryRoot ?? target.Root, folder.Replace('/', Path.DirectorySeparatorChar));
                if (!Directory.Exists(directory)) continue;
                foreach (var skillDirectory in Directory.EnumerateDirectories(directory).Order(StringComparer.Ordinal))
                {
                    if (!File.Exists(Path.Combine(skillDirectory, "SKILL.md"))) continue;
                    var name = Path.GetFileName(skillDirectory);
                    var key = $"repo:{folder}/{name}";
                    byKey[key] = new Skill
                    {
                        Key = key,
                        FolderName = name,
                        Origin = SkillOrigin.Repository,
                        Directory = skillDirectory,
                        Files = ListFiles(skillDirectory),
                    };
                }
            }
        }

        result.Skills.AddRange(byKey.Values.OrderBy(s => s.Origin).ThenBy(s => s.Key, StringComparer.Ordinal));
        return result;
    }

    private static void ReadAssets(string root, string assetsFile, Dictionary<string, Skill> byKey, DiscoveryResult result)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(assetsFile));
        var json = document.RootElement;

        var project = ProjectName(root, assetsFile, json);
        var direct = DirectDependencies(json);
        var packageFolders = json.TryGetProperty("packageFolders", out var folders)
            ? folders.EnumerateObject().Select(f => f.Name).ToList()
            : [];

        if (!json.TryGetProperty("libraries", out var libraries)) return;

        foreach (var library in libraries.EnumerateObject())
        {
            var value = library.Value;
            if (!value.TryGetProperty("type", out var type) || type.GetString() != "package") continue;
            if (!value.TryGetProperty("files", out var files)) continue;

            var skillNames = files.EnumerateArray()
                .Select(f => f.GetString() ?? "")
                .Select(f => PackageSkillFile.Match(f))
                .Where(m => m.Success)
                .Select(m => m.Groups[1].Value)
                .Distinct(StringComparer.Ordinal)
                .ToList();
            if (skillNames.Count == 0) continue;

            var slash = library.Name.IndexOf('/');
            var id = slash > 0 ? library.Name[..slash] : library.Name;
            var version = slash > 0 ? library.Name[(slash + 1)..] : "";
            var relative = value.TryGetProperty("path", out var p) ? p.GetString() ?? "" : $"{id.ToLowerInvariant()}/{version.ToLowerInvariant()}";

            var packageDirectory = packageFolders
                .Select(f => Path.Combine(f, relative.Replace('/', Path.DirectorySeparatorChar)))
                .FirstOrDefault(Directory.Exists);
            if (packageDirectory is null)
            {
                result.Problems.Add($"{id} {version} declares skills but is not in the packages folder; run dotnet restore.");
                continue;
            }

            var allFiles = files.EnumerateArray().Select(f => f.GetString() ?? "").ToList();
            foreach (var name in skillNames)
            {
                var key = $"nuget:{id.ToLowerInvariant()}/{name}";
                if (byKey.TryGetValue(key, out var existing))
                {
                    if (!existing.Projects.Contains(project)) existing.Projects.Add(project);
                    if (!string.Equals(existing.PackageVersion, version, StringComparison.OrdinalIgnoreCase))
                        result.Problems.Add($"{id} is restored at {existing.PackageVersion} and {version} in different projects; auditing {existing.PackageVersion}.");
                    continue;
                }

                var prefix = $"skills/{name}/";
                var skillFiles = allFiles
                    .Where(f => f.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    .Select(f => f[prefix.Length..])
                    .Where(IsSafeRelativePath)
                    .Order(StringComparer.Ordinal)
                    .ToList();

                var skill = new Skill
                {
                    Key = key,
                    FolderName = name,
                    Origin = SkillOrigin.Package,
                    Directory = Path.Combine(packageDirectory, "skills", name),
                    Files = skillFiles,
                    PackageId = id,
                    PackageVersion = version,
                    IsDirectDependency = direct.Contains(id),
                };
                skill.Projects.Add(project);
                byKey[key] = skill;
            }
        }
    }

    private static string ProjectName(string root, string assetsFile, JsonElement json)
    {
        if (json.TryGetProperty("project", out var project)
            && project.TryGetProperty("restore", out var restore)
            && restore.TryGetProperty("projectPath", out var projectPath)
            && projectPath.GetString() is { } path)
        {
            var relative = Path.GetRelativePath(root, path);
            return relative.StartsWith("..", StringComparison.Ordinal) ? Path.GetFileName(path) : relative.Replace('\\', '/');
        }
        return Path.GetRelativePath(root, assetsFile).Replace('\\', '/');
    }

    private static HashSet<string> DirectDependencies(JsonElement json)
    {
        var direct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (json.TryGetProperty("project", out var project) && project.TryGetProperty("frameworks", out var frameworks))
        {
            foreach (var framework in frameworks.EnumerateObject())
                if (framework.Value.TryGetProperty("dependencies", out var dependencies))
                    foreach (var dependency in dependencies.EnumerateObject())
                        direct.Add(dependency.Name);
        }
        return direct;
    }

    private static List<string> ListFiles(string directory) =>
        Directory.EnumerateFiles(directory, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 })
            .Select(f => Path.GetRelativePath(directory, f).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToList();

    private static bool IsSafeRelativePath(string path) =>
        path.Length > 0 && !path.Split('/').Any(segment => segment is ".." or "") && !Path.IsPathRooted(path);
}

public sealed class DiscoveryResult
{
    public List<Skill> Skills { get; } = [];

    /// <summary>Things that stopped a package from being audited (not restored, unreadable assets file).</summary>
    public List<string> Problems { get; } = [];
}
