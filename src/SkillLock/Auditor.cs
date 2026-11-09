namespace SkillLock;

public sealed class AuditOptions
{
    /// <summary>Explicit lock file; otherwise searched from the root upwards.</summary>
    public string? LockPath { get; init; }

    /// <summary>New or changed skills are errors (CI) instead of warnings (local builds).</summary>
    public bool Locked { get; init; } = true;
}

public sealed class AuditResult
{
    public required AuditTarget Target { get; init; }
    public List<Skill> Skills { get; } = [];
    public List<Finding> Findings { get; } = [];
    public List<SkillStatus> Statuses { get; } = [];
    public Dictionary<string, SortedDictionary<string, string>> FileHashes { get; } = new(StringComparer.Ordinal);
    public string? LockPath { get; set; }
    public LockFile? Lock { get; set; }

    public IEnumerable<Finding> Active => Findings.Where(f => !f.Accepted);

    public int Count(Severity severity) => Active.Count(f => f.Severity == severity);

    public bool Fails(Severity? failOn) => failOn is { } threshold && Active.Any(f => f.Severity >= threshold);

    public SkillStatus? StatusOf(Skill skill) => Statuses.FirstOrDefault(s => s.Key == skill.Key);
}

public static class Auditor
{
    public static AuditResult Run(AuditTarget target, AuditOptions options)
    {
        var discovery = SkillDiscovery.Discover(target);
        var result = new AuditResult { Target = target };
        result.Skills.AddRange(discovery.Skills);

        foreach (var problem in discovery.Problems)
            result.Findings.Add(Scanner.Create(Rules.PackageNotRestored, null, problem, null, null, 0, 0, null, problem));

        foreach (var skill in result.Skills)
        {
            result.Findings.AddRange(Scanner.Scan(skill));
            result.FileHashes[skill.Key] = SkillHasher.HashFiles(skill);
        }

        AddCollisions(result);

        result.LockPath = options.LockPath is not null ? Path.GetFullPath(options.LockPath) : LockFile.Find(target.Root);
        if (result.LockPath is not null && File.Exists(result.LockPath))
        {
            result.Lock = LockFile.Load(result.LockPath);
            CompareWithLock(result, result.Lock, options.Locked, reportRemoved: target.IncludeRepositorySkills && !target.PackageFindingsOnly);
        }
        else
        {
            foreach (var skill in result.Skills)
                result.Statuses.Add(new SkillStatus(skill, skill.Key, LockState.Unlocked, []));
        }

        if (target.PackageFindingsOnly)
        {
            result.Findings.RemoveAll(f => f.Skill?.Origin == SkillOrigin.Repository);
            result.Statuses.RemoveAll(s => s.Skill?.Origin == SkillOrigin.Repository);
            result.Skills.RemoveAll(s => s.Origin == SkillOrigin.Repository);
        }

        return result;
    }

    private static void AddCollisions(AuditResult result)
    {
        foreach (var group in result.Skills.GroupBy(s => s.DeclaredName ?? s.FolderName, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
        {
            foreach (var skill in group.Where(s => s.Origin == SkillOrigin.Package))
            {
                var others = string.Join(", ", group.Where(o => o != skill).Select(o => o.SourceDisplay));
                result.Findings.Add(Scanner.Create(Rules.NameCollision, null,
                    $"Skill \"{group.Key}\" is also provided by {others}; the agent may load either",
                    skill, "SKILL.md", 1, 1, null, $"{group.Key}|{string.Join("|", group.Select(g => g.Key).Order(StringComparer.Ordinal))}"));
            }
        }
    }

    private static void CompareWithLock(AuditResult result, LockFile lockFile, bool locked, bool reportRemoved)
    {
        var lockSeverity = locked ? Severity.Error : Severity.Warning;

        foreach (var skill in result.Skills)
        {
            var hashes = result.FileHashes[skill.Key];
            if (!lockFile.Skills.TryGetValue(skill.Key, out var entry))
            {
                result.Statuses.Add(new SkillStatus(skill, skill.Key, LockState.New, []));
                result.Findings.Add(Scanner.Create(Rules.NewSkill, lockSeverity,
                    $"New skill from {skill.SourceDisplay} has not been reviewed; review it, then run skilllock lock",
                    skill, "SKILL.md", 1, 1, null, $"new|{skill.Key}|{SkillHasher.Combine(hashes)}"));
                continue;
            }

            var accepted = entry.Accepted ?? [];
            foreach (var finding in result.Findings.Where(f => f.Skill == skill))
                if (accepted.Any(a => a.Rule == finding.Rule.Id && a.Fingerprint == finding.Fingerprint))
                    finding.Accepted = true;

            var combined = SkillHasher.Combine(hashes);
            if (string.Equals(combined, entry.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                result.Statuses.Add(new SkillStatus(skill, skill.Key, LockState.Locked, []));
                continue;
            }

            var changed = new List<string>();
            foreach (var (file, hash) in hashes)
            {
                if (!entry.Files.TryGetValue(file, out var old)) changed.Add($"+{file}");
                else if (!string.Equals(old, hash, StringComparison.OrdinalIgnoreCase)) changed.Add($"~{file}");
            }
            changed.AddRange(entry.Files.Keys.Where(f => !hashes.ContainsKey(f)).Select(f => $"-{f}"));

            result.Statuses.Add(new SkillStatus(skill, skill.Key, LockState.Changed, changed));
            var from = entry.Source is not null && entry.Source != LockSource(skill) ? $" (was {entry.Source})" : "";
            result.Findings.Add(Scanner.Create(Rules.ChangedSkill, lockSeverity,
                $"Skill from {skill.SourceDisplay}{from} changed since it was reviewed: {Describe(changed)}; review it, then run skilllock lock",
                skill, changed.Select(c => c[1..]).FirstOrDefault(f => skill.Files.Contains(f)) ?? "SKILL.md", 1, 1, null, $"changed|{skill.Key}|{combined}"));
        }

        if (!reportRemoved) return;
        foreach (var (key, entry) in lockFile.Skills.Where(e => result.Skills.All(s => s.Key != e.Key)))
        {
            result.Statuses.Add(new SkillStatus(null, key, LockState.Removed, []));
            result.Findings.Add(Scanner.Create(Rules.RemovedSkill, null,
                $"Locked skill {key} ({entry.Source}) is no longer present; run skilllock lock to drop it", null, null, 0, 0, null, key));
        }
    }

    private static string LockSource(Skill skill) =>
        skill.Origin == SkillOrigin.Package ? $"{skill.PackageId} {skill.PackageVersion}" : "repository";

    private static string Describe(List<string> changed)
    {
        var parts = changed.Select(c => c[0] switch { '+' => $"{c[1..]} added", '-' => $"{c[1..]} removed", _ => $"{c[1..]} modified" }).ToList();
        return parts.Count <= 4 ? string.Join(", ", parts) : $"{string.Join(", ", parts.Take(4))} and {parts.Count - 4} more";
    }

    /// <summary>
    /// The lock file for the current state. Findings at warning or above are recorded as accepted: locking is the review.
    /// When the target does not cover the whole repository, entries for skills outside it are kept.
    /// </summary>
    public static LockFile CreateLock(AuditResult result)
    {
        var lockFile = new LockFile();
        if (result.Lock is not null && (!result.Target.IncludeRepositorySkills || result.Target.PackageFindingsOnly))
            foreach (var (key, entry) in result.Lock.Skills) lockFile.Skills[key] = entry;

        foreach (var skill in result.Skills)
        {
            var hashes = result.FileHashes[skill.Key];
            var accepted = result.Findings
                .Where(f => f.Skill == skill && f.Severity >= Severity.Warning && f.Rule != Rules.NewSkill && f.Rule != Rules.ChangedSkill)
                .Select(f => new AcceptedFinding { Rule = f.Rule.Id, Fingerprint = f.Fingerprint, File = f.File, Evidence = f.Evidence })
                .GroupBy(a => (a.Rule, a.Fingerprint)).Select(g => g.First())
                .ToList();

            lockFile.Skills[skill.Key] = new LockedSkill
            {
                Name = skill.DeclaredName ?? skill.FolderName,
                Source = LockSource(skill),
                Sha256 = SkillHasher.Combine(hashes),
                Files = hashes,
                Accepted = accepted.Count > 0 ? accepted : null,
            };
        }
        return lockFile;
    }
}
