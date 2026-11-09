using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SkillLock;

public static class ToolInfo
{
    public static string Version { get; } =
        (typeof(ToolInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0").Split('+')[0];

    public const string Uri = "https://github.com/amondejar/skill-lock";
}

public static class TextReporter
{
    public static void Write(AuditResult result, TextWriter output, bool verbose, bool color)
    {
        string C(string code, string text) => color ? $"\u001b[{code}m{text}\u001b[0m" : text;
        string Sev(Severity s) => s switch { Severity.Error => C("31", "error  "), Severity.Warning => C("33", "warning"), _ => C("36", "info   ") };

        var packages = result.Skills.Count(s => s.Origin == SkillOrigin.Package);
        var repository = result.Skills.Count - packages;
        var lockText = result.Lock is null ? "no lock file" : $"lock: {Relative(result.Target.Root, result.LockPath!)}";
        output.WriteLine($"SkillLock {ToolInfo.Version} · {Plural(result.Skills.Count, "skill")} ({packages} from packages, {repository} in the repository) · {lockText}");
        output.WriteLine();

        if (result.Skills.Count == 0 && result.Target.AssetsFiles.Count == 0 && !result.Target.IncludeRepositorySkills)
            output.WriteLine("  No project.assets.json found. Run dotnet restore first, or pass --assets.");

        var nameWidth = Math.Min(32, result.Skills.Select(s => (s.DeclaredName ?? s.FolderName).Length).DefaultIfEmpty(10).Max());
        var sourceWidth = Math.Min(44, result.Skills.Select(s => s.SourceDisplay.Length).DefaultIfEmpty(10).Max());

        foreach (var skill in result.Skills)
        {
            var findings = result.Findings.Where(f => f.Skill == skill && !f.Accepted && (verbose || f.Severity > Severity.Info))
                .OrderBy(f => f.Rule.Id.StartsWith("SKL1", StringComparison.Ordinal) ? 0 : 1)
                .ThenBy(f => f.File?.Equals("SKILL.md", StringComparison.OrdinalIgnoreCase) == true ? 0 : 1)
                .ThenBy(f => f.File, StringComparer.Ordinal).ThenBy(f => f.Line)
                .ToList();
            var status = result.StatusOf(skill);
            var worst = findings.Select(f => f.Severity).DefaultIfEmpty(Severity.Info).Max();
            var mark = findings.Count == 0 ? C("32", "✓") : worst == Severity.Error ? C("31", "✗") : worst == Severity.Warning ? C("33", "!") : C("36", "·");
            var state = status?.State switch
            {
                LockState.Locked => C("32", "locked"),
                LockState.New => C("31", "new"),
                LockState.Changed => C("31", "changed"),
                _ => C("90", "not locked"),
            };
            output.WriteLine($"  {mark} {Pad(skill.DeclaredName ?? skill.FolderName, nameWidth)}  {Pad(skill.SourceDisplay, sourceWidth)}  {state}");

            foreach (var finding in findings)
            {
                var where = finding.Line > 0 ? $"{finding.File}:{finding.Line}" : finding.File;
                output.WriteLine($"      {Sev(finding.Severity)} {finding.Rule.Id}  {C("90", where ?? "")}  {finding.Message}");
                if (!string.IsNullOrEmpty(finding.Evidence) && finding.Evidence != finding.File)
                    output.WriteLine($"                     {C("90", finding.Evidence)}");
            }
        }

        foreach (var finding in result.Findings.Where(f => f.Skill is null && !f.Accepted && (verbose || f.Severity > Severity.Info)))
            output.WriteLine($"  {Sev(finding.Severity)} {finding.Rule.Id}  {finding.Message}");

        var accepted = result.Findings.Count(f => f.Accepted);
        var hiddenInfo = verbose ? 0 : result.Count(Severity.Info);
        output.WriteLine();
        var summary = $"  {Plural(result.Count(Severity.Error), "error")} · {Plural(result.Count(Severity.Warning), "warning")} · {result.Count(Severity.Info)} info";
        if (accepted > 0) summary += $" · {accepted} accepted in the lock file";
        if (hiddenInfo > 0) summary += " (--verbose shows info)";
        output.WriteLine(summary);
    }

    private static string Pad(string text, int width) => text.Length > width ? text[..(width - 1)] + "…" : text.PadRight(width);
    private static string Plural(int count, string word) => $"{count} {word}{(count == 1 ? "" : "s")}";
    internal static string Relative(string root, string path) => Path.GetRelativePath(root, path).Replace('\\', '/');
}

public static class JsonReporter
{
    public static string Write(AuditResult result)
    {
        var skills = new JsonArray();
        foreach (var skill in result.Skills)
        {
            var status = result.StatusOf(skill);
            skills.Add(new JsonObject
            {
                ["key"] = skill.Key,
                ["name"] = skill.DeclaredName ?? skill.FolderName,
                ["origin"] = skill.Origin == SkillOrigin.Package ? "package" : "repository",
                ["package"] = skill.PackageId,
                ["version"] = skill.PackageVersion,
                ["direct"] = skill.Origin == SkillOrigin.Package ? skill.IsDirectDependency : null,
                ["projects"] = new JsonArray(skill.Projects.Select(p => (JsonNode?)p).ToArray()),
                ["directory"] = skill.Directory,
                ["sha256"] = result.FileHashes.TryGetValue(skill.Key, out var h) ? SkillHasher.Combine(h) : null,
                ["status"] = (status?.State ?? LockState.Unlocked).ToString().ToLowerInvariant(),
                ["changedFiles"] = status is { ChangedFiles.Count: > 0 } ? new JsonArray(status.ChangedFiles.Select(c => (JsonNode?)c).ToArray()) : null,
                ["findings"] = Findings(result.Findings.Where(f => f.Skill == skill)),
            });
        }

        var root = new JsonObject
        {
            ["tool"] = "SkillLock",
            ["version"] = ToolInfo.Version,
            ["root"] = result.Target.Root,
            ["lockFile"] = result.LockPath is not null && result.Lock is not null ? result.LockPath : null,
            ["summary"] = new JsonObject
            {
                ["skills"] = result.Skills.Count,
                ["errors"] = result.Count(Severity.Error),
                ["warnings"] = result.Count(Severity.Warning),
                ["info"] = result.Count(Severity.Info),
                ["accepted"] = result.Findings.Count(f => f.Accepted),
            },
            ["skills"] = skills,
            ["findings"] = Findings(result.Findings.Where(f => f.Skill is null)),
        };
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    private static JsonArray Findings(IEnumerable<Finding> findings) => new(findings.Select(f => (JsonNode?)new JsonObject
    {
        ["rule"] = f.Rule.Id,
        ["name"] = f.Rule.Name,
        ["severity"] = f.Severity.ToString().ToLowerInvariant(),
        ["message"] = f.Message,
        ["file"] = f.File,
        ["line"] = f.Line > 0 ? f.Line : null,
        ["column"] = f.Column > 0 ? f.Column : null,
        ["evidence"] = f.Evidence,
        ["fingerprint"] = f.Fingerprint,
        ["accepted"] = f.Accepted,
    }).ToArray());
}

public static class SarifReporter
{
    /// <summary>Info findings are left out unless asked for: code scanning would list each one as an alert.</summary>
    public static string Write(AuditResult result, bool includeInfo = false)
    {
        var root = result.Target.Root;
        var anchor = result.LockPath is not null && File.Exists(result.LockPath) ? result.LockPath : null;

        var rules = new JsonArray(Rules.All.Select(r => (JsonNode?)new JsonObject
        {
            ["id"] = r.Id,
            ["name"] = r.Name,
            ["shortDescription"] = new JsonObject { ["text"] = r.Title },
            ["fullDescription"] = new JsonObject { ["text"] = r.Description },
            ["helpUri"] = r.HelpUri,
            ["defaultConfiguration"] = new JsonObject { ["level"] = Level(r.Severity) },
        }).ToArray());

        var results = new JsonArray();
        foreach (var finding in result.Findings.Where(f => includeInfo || f.Severity > Severity.Info))
        {
            var message = finding.Skill is { } skill && finding.File is not null
                ? $"{finding.Message} — {skill.DisplayPath(finding.File)}{(finding.Line > 0 ? $":{finding.Line}" : "")}"
                : finding.Message;
            if (!string.IsNullOrEmpty(finding.Evidence) && finding.Evidence != finding.File) message += $"\n{finding.Evidence}";

            var entry = new JsonObject
            {
                ["ruleId"] = finding.Rule.Id,
                ["level"] = Level(finding.Severity),
                ["message"] = new JsonObject { ["text"] = message },
                ["partialFingerprints"] = new JsonObject { ["skilllock/v1"] = finding.Fingerprint },
            };

            var location = Location(root, finding, anchor);
            if (location is not null) entry["locations"] = new JsonArray(location);
            if (finding.Accepted)
                entry["suppressions"] = new JsonArray(new JsonObject { ["kind"] = "external", ["justification"] = "Accepted in skills.lock.json" });
            results.Add(entry);
        }

        var sarif = new JsonObject
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(new JsonObject
            {
                ["tool"] = new JsonObject
                {
                    ["driver"] = new JsonObject
                    {
                        ["name"] = "SkillLock",
                        ["version"] = ToolInfo.Version,
                        ["semanticVersion"] = ToolInfo.Version,
                        ["informationUri"] = ToolInfo.Uri,
                        ["rules"] = rules,
                    },
                },
                ["originalUriBaseIds"] = new JsonObject
                {
                    ["SRCROOT"] = new JsonObject { ["uri"] = new Uri(root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar).AbsoluteUri },
                },
                ["results"] = results,
            }),
        };
        return sarif.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    /// <summary>
    /// Repository files get their real location. Package files live in the NuGet cache (even when it sits inside the
    /// checkout, it is not versioned), which code scanning cannot show, so those findings point at the lock file
    /// (or the project that references the package); the message carries the package path and line.
    /// </summary>
    private static JsonObject? Location(string root, Finding finding, string? anchor)
    {
        string? path = finding.AbsolutePath;
        var region = finding.Line > 0;
        if (path is null || finding.Skill?.Origin == SkillOrigin.Package || !IsUnder(root, path))
        {
            region = false;
            path = anchor;
            if (path is null && finding.Skill?.Projects.FirstOrDefault() is { } project) path = Path.Combine(root, project);
        }
        if (path is null) return null;

        var physical = new JsonObject
        {
            ["artifactLocation"] = IsUnder(root, path)
                ? new JsonObject { ["uri"] = TextReporter.Relative(root, path), ["uriBaseId"] = "SRCROOT" }
                : new JsonObject { ["uri"] = new Uri(path).AbsoluteUri },
        };
        if (region)
            physical["region"] = new JsonObject { ["startLine"] = finding.Line, ["startColumn"] = Math.Max(1, finding.Column) };
        return new JsonObject { ["physicalLocation"] = physical };
    }

    private static bool IsUnder(string root, string path)
    {
        var relative = Path.GetRelativePath(root, path);
        return !relative.StartsWith("..", StringComparison.Ordinal) && !Path.IsPathRooted(relative);
    }

    private static string Level(Severity severity) => severity switch { Severity.Error => "error", Severity.Warning => "warning", _ => "note" };
}

/// <summary>Lines in the canonical format MSBuild turns into build errors and warnings (and the IDE error list).</summary>
public static class MSBuildReporter
{
    public static void Write(AuditResult result, TextWriter output, Severity? failOn)
    {
        foreach (var finding in result.Active)
        {
            var category = finding.Severity switch
            {
                Severity.Info => null,
                _ when failOn is null => "warning",
                _ when finding.Severity >= failOn => "error",
                _ => "warning",
            };

            var where = finding.Skill is { } skill ? $" [{skill.SourceDisplay} › {skill.FolderName}]" : "";
            var evidence = !string.IsNullOrEmpty(finding.Evidence) && finding.Evidence != finding.File ? $": {finding.Evidence}" : "";
            var text = $"{finding.Message}{evidence}{where}";

            if (category is null)
            {
                output.WriteLine($"SkillLock: info {finding.Rule.Id}: {text}");
                continue;
            }

            var origin = finding.AbsolutePath is { } path
                ? finding.Line > 0 ? $"{path}({finding.Line},{Math.Max(1, finding.Column)})" : path
                : "SkillLock";
            output.WriteLine($"{origin}: {category} {finding.Rule.Id}: {text}");
        }
    }
}

internal static class Text
{
    public static readonly Encoding Utf8 = new UTF8Encoding(false);
}
