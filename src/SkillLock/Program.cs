using SkillLock;

Console.OutputEncoding = Text.Utf8;
return Cli.Run(args, Console.Out, Console.Error);

namespace SkillLock
{
    public static class Cli
    {
        private const string Usage = """
            SkillLock — audits the agent skills (SKILL.md) your NuGet packages and repository bring in.

            Usage:
              skilllock scan   [path] [options]   Analyze skills and report findings
              skilllock lock   [path] [options]   Record the reviewed skills in skills.lock.json
              skilllock verify [path] [options]   Fail if a skill is new, changed or unsafe (for CI)
              skilllock rules                     List the rules

            path: a directory (default: current; every restored project under it plus .agents/.claude/.github skills),
                  a project file, a solution (.sln/.slnx) or a project.assets.json.

            Options:
              --format text|json|sarif   Output format (default: text)
              --output <file>            Write the report to a file
              --fail-on error|warning|info|none
                                         Lowest severity that fails (default: error)
              --lock <file>              Lock file (default: skills.lock.json in the path or a parent, up to the repo root)
              --assets <file>            A project.assets.json to audit (repeatable)
              --no-repo                  Skip the repository skill folders
              --accept-findings          lock: record error findings as accepted after review
              --verbose                  Include info findings (text and SARIF)
              --no-color                 Plain output

            Exit codes: 0 ok, 1 findings at or above --fail-on, 2 usage or configuration error.
            """;

        public static int Run(string[] args, TextWriter stdout, TextWriter stderr)
        {
            try
            {
                if (args.Length == 0 || args[0] is "-h" or "--help" or "help") { stdout.WriteLine(Usage); return args.Length == 0 ? 2 : 0; }
                if (args[0] is "--version" or "-v") { stdout.WriteLine(ToolInfo.Version); return 0; }

                var command = args[0];
                var options = Options.Parse(args.Skip(1).ToArray());
                return command switch
                {
                    "scan" => Scan(options, stdout, verify: false),
                    "verify" => Scan(options, stdout, verify: true),
                    "lock" => Lock(options, stdout),
                    "rules" => ListRules(stdout),
                    _ => throw new SkillLockException($"Unknown command '{command}'. Run skilllock --help."),
                };
            }
            catch (SkillLockException e)
            {
                stderr.WriteLine($"skilllock: {e.Message}");
                return 2;
            }
        }

        private static int Scan(Options options, TextWriter stdout, bool verify)
        {
            var target = AuditTarget.Resolve(options.Path, options.Assets, options.NoRepo ? false : null);
            if (options.MSBuild && !options.NoRepo)
                target = target with { IncludeRepositorySkills = true, PackageFindingsOnly = true, RepositoryRoot = AuditTarget.FindRepositoryRoot(target.Root) };

            if (verify && !options.MSBuild)
            {
                var lockPath = options.LockFile ?? LockFile.Find(target.Root);
                if (lockPath is null || !File.Exists(lockPath))
                    throw new SkillLockException($"No {LockFile.FileName} found from {target.Root}. Review the skills with 'skilllock scan', then create it with 'skilllock lock'.");
            }

            // verify: new or changed skills are errors. scan: warnings. MSBuild: errors only in locked mode (CI).
            var locked = options.MSBuild ? options.Locked ?? false : verify;
            var result = Auditor.Run(target, new AuditOptions { LockPath = options.LockFile, Locked = locked });

            if (options.MSBuild)
            {
                MSBuildReporter.Write(result, stdout, options.FailOn);
                return 0; // MSBuild decides from the error lines; a crash here must not break the build silently
            }

            Report(result, options, stdout);
            return result.Fails(options.FailOn) ? 1 : 0;
        }

        private static int Lock(Options options, TextWriter stdout)
        {
            var target = AuditTarget.Resolve(options.Path, options.Assets, options.NoRepo ? false : null);
            var result = Auditor.Run(target, new AuditOptions { LockPath = options.LockFile, Locked = false });

            var blocking = result.Active.Where(f => f.Severity == Severity.Error && f.Skill is not null && f.Rule != Rules.NewSkill && f.Rule != Rules.ChangedSkill).ToList();
            if (blocking.Count > 0 && !options.AcceptFindings)
            {
                TextReporter.Write(result, stdout, options.Verbose, options.Color);
                stdout.WriteLine();
                stdout.WriteLine($"Not locked: {blocking.Select(f => f.Skill).Distinct().Count()} skill(s) have errors. Review them; if they are fine, run skilllock lock --accept-findings to record them as accepted.");
                return 1;
            }

            var lockPath = result.LockPath ?? options.LockFile ?? LockFile.DefaultPath(target.Root);
            var lockFile = Auditor.CreateLock(result);
            lockFile.Save(lockPath);

            var counts = result.Statuses.GroupBy(s => s.State).ToDictionary(g => g.Key, g => g.Count());
            var parts = new List<string>();
            if (counts.GetValueOrDefault(LockState.New) + counts.GetValueOrDefault(LockState.Unlocked) is var added and > 0) parts.Add($"{added} added");
            if (counts.GetValueOrDefault(LockState.Changed) is var changed and > 0) parts.Add($"{changed} updated");
            if (counts.GetValueOrDefault(LockState.Removed) is var removed and > 0) parts.Add($"{removed} removed");
            var accepted = lockFile.Skills.Values.Sum(s => s.Accepted?.Count ?? 0);
            if (accepted > 0) parts.Add($"{accepted} finding(s) accepted");

            stdout.WriteLine($"Locked {result.Skills.Count} skill(s) in {TextReporter.Relative(Directory.GetCurrentDirectory(), lockPath)}{(parts.Count > 0 ? $" ({string.Join(", ", parts)})" : "")}.");
            stdout.WriteLine("Commit the lock file: from now on, skilllock verify and the SkillLock package flag any skill that is added or changes.");
            return 0;
        }

        private static void Report(AuditResult result, Options options, TextWriter stdout)
        {
            var content = options.Format switch
            {
                "json" => JsonReporter.Write(result),
                "sarif" => SarifReporter.Write(result, includeInfo: options.Verbose),
                _ => null,
            };

            if (content is null)
            {
                if (options.Output is null) { TextReporter.Write(result, stdout, options.Verbose, options.Color); return; }
                using var writer = new StringWriter();
                TextReporter.Write(result, writer, options.Verbose, color: false);
                content = writer.ToString();
            }

            if (options.Output is null) { stdout.WriteLine(content); return; }

            var output = Path.GetFullPath(options.Output);
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            File.WriteAllText(output, content, Text.Utf8);
            // Keep a short human summary on the console when the report goes to a file.
            stdout.WriteLine($"SkillLock: {result.Skills.Count} skill(s), {result.Count(Severity.Error)} error(s), {result.Count(Severity.Warning)} warning(s). Report: {options.Output}");
        }

        private static int ListRules(TextWriter stdout)
        {
            foreach (var rule in Rules.All)
                stdout.WriteLine($"{rule.Id}  {rule.Severity.ToString().ToLowerInvariant(),-7}  {rule.Name,-24} {rule.Title}");
            return 0;
        }

        private sealed class Options
        {
            public string Path { get; private set; } = ".";
            public string Format { get; private set; } = "text";
            public string? Output { get; private set; }
            public Severity? FailOn { get; private set; } = Severity.Error;
            public string? LockFile { get; private set; }
            public List<string> Assets { get; } = [];
            public bool NoRepo { get; private set; }
            public bool AcceptFindings { get; private set; }
            public bool Verbose { get; private set; }
            public bool Color { get; private set; } =
                Environment.GetEnvironmentVariable("NO_COLOR") is null
                && (!Console.IsOutputRedirected || Environment.GetEnvironmentVariable("FORCE_COLOR") is not null);
            public bool MSBuild { get; private set; }
            public bool? Locked { get; private set; }

            public static Options Parse(string[] args)
            {
                var options = new Options();
                var pathSet = false;
                for (var i = 0; i < args.Length; i++)
                {
                    var arg = args[i];
                    string Value() => i + 1 < args.Length ? args[++i] : throw new SkillLockException($"{arg} needs a value.");
                    switch (arg)
                    {
                        case "--format":
                            options.Format = Value().ToLowerInvariant();
                            if (options.Format is not ("text" or "json" or "sarif")) throw new SkillLockException("--format must be text, json or sarif.");
                            break;
                        case "--output" or "-o": options.Output = Value(); break;
                        case "--fail-on": options.FailOn = ParseSeverity(Value()); break;
                        case "--lock": options.LockFile = Value(); break;
                        case "--assets": options.Assets.Add(Value()); break;
                        case "--no-repo": options.NoRepo = true; break;
                        case "--accept-findings": options.AcceptFindings = true; break;
                        case "--verbose": options.Verbose = true; break;
                        case "--no-color": options.Color = false; break;
                        case "--msbuild": options.MSBuild = true; options.Color = false; break;
                        case "--locked": options.Locked = Value().Equals("true", StringComparison.OrdinalIgnoreCase); break;
                        default:
                            if (arg.StartsWith('-')) throw new SkillLockException($"Unknown option {arg}.");
                            if (pathSet) throw new SkillLockException($"Unexpected argument {arg}.");
                            options.Path = arg;
                            pathSet = true;
                            break;
                    }
                }
                if (string.IsNullOrWhiteSpace(options.LockFile)) options.LockFile = null;
                return options;
            }

            private static Severity? ParseSeverity(string value) => value.ToLowerInvariant() switch
            {
                "error" => Severity.Error,
                "warning" => Severity.Warning,
                "info" => Severity.Info,
                "none" => null,
                _ => throw new SkillLockException("--fail-on must be error, warning, info or none."),
            };
        }
    }
}
