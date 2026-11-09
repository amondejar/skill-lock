using System.Text.Json.Nodes;

namespace SkillLock.Tests;

/// <summary>A throwaway repository with a restored project: an assets file, a packages folder and repository skills.</summary>
public sealed class TestRepo : IDisposable
{
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "skilllock-tests", Guid.NewGuid().ToString("N"));
    public string PackagesFolder => Path.Combine(Root, ".packages");
    public string ProjectDirectory => Path.Combine(Root, "src", "App");
    public string AssetsFile => Path.Combine(ProjectDirectory, "obj", "project.assets.json");

    private readonly List<(string Id, string Version, bool Direct, Dictionary<string, string> Files)> _packages = [];

    public TestRepo()
    {
        Directory.CreateDirectory(Path.Combine(Root, ".git"));
        Directory.CreateDirectory(ProjectDirectory);
    }

    /// <summary>Adds a package with files (paths inside the package, e.g. skills/x/SKILL.md).</summary>
    public TestRepo Package(string id, string version, Dictionary<string, string> files, bool direct = true)
    {
        _packages.RemoveAll(p => p.Id == id);
        _packages.Add((id, version, direct, files));
        var directory = Path.Combine(PackagesFolder, id.ToLowerInvariant(), version.ToLowerInvariant());
        if (Directory.Exists(directory)) Directory.Delete(directory, true);
        foreach (var (path, content) in files) Write(Path.Combine(directory, path), content);
        WriteAssets();
        return this;
    }

    public TestRepo PackageSkill(string id, string skillName, string skillMd, string version = "1.0.0", bool direct = true) =>
        Package(id, version, new() { [$"skills/{skillName}/SKILL.md"] = skillMd, [$"lib/net8.0/{id}.dll"] = "x" }, direct);

    public TestRepo RepoSkill(string folder, string name, string skillMd)
    {
        Write(Path.Combine(Root, folder, name, "SKILL.md"), skillMd);
        return this;
    }

    public static string Skill(string name, string body = "Use it well.", string? extraFrontmatter = null) =>
        $"---\nname: {name}\ndescription: Use when testing SkillLock with a {name} skill.\n{(extraFrontmatter is null ? "" : extraFrontmatter + "\n")}---\n\n# {name}\n\n{body}\n";

    public static void Write(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private void WriteAssets()
    {
        var libraries = new JsonObject();
        foreach (var (id, version, _, files) in _packages)
        {
            libraries[$"{id}/{version}"] = new JsonObject
            {
                ["sha512"] = "x",
                ["type"] = "package",
                ["path"] = $"{id.ToLowerInvariant()}/{version.ToLowerInvariant()}",
                ["files"] = new JsonArray(files.Keys.Concat([$"{id.ToLowerInvariant()}.nuspec"]).Select(f => (JsonNode?)f).ToArray()),
            };
        }
        libraries["Other.Project/1.0.0"] = new JsonObject { ["type"] = "project", ["path"] = "../Other/Other.csproj" };

        var dependencies = new JsonObject();
        foreach (var (id, version, direct, _) in _packages.Where(p => p.Direct))
            dependencies[id] = new JsonObject { ["target"] = "Package", ["version"] = $"[{version}, )" };

        var assets = new JsonObject
        {
            ["version"] = 3,
            ["libraries"] = libraries,
            ["packageFolders"] = new JsonObject { [PackagesFolder + Path.DirectorySeparatorChar] = new JsonObject() },
            ["project"] = new JsonObject
            {
                ["restore"] = new JsonObject { ["projectPath"] = Path.Combine(ProjectDirectory, "App.csproj") },
                ["frameworks"] = new JsonObject { ["net8.0"] = new JsonObject { ["dependencies"] = dependencies } },
            },
        };
        Write(AssetsFile, assets.ToJsonString());
    }

    public AuditResult Audit(bool locked = true) =>
        Auditor.Run(AuditTarget.Resolve(Root), new AuditOptions { Locked = locked });

    /// <summary>Runs a command against the repository root (passed as the path, so tests don't touch the current directory).</summary>
    public (int Exit, string Output) Cli(string command, params string[] args)
    {
        var output = new StringWriter();
        var exit = SkillLock.Cli.Run([command, Root, .. args, "--no-color"], output, output);
        return (exit, output.ToString());
    }

    public void Dispose()
    {
        try { Directory.Delete(Root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
