using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SkillLock;

/// <summary>Static analysis of a skill's files. Never executes or fetches anything.</summary>
public static class Scanner
{
    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);
    private const int MaxScannedBytes = 2 * 1024 * 1024;
    private const int LargeSkillBytes = 32 * 1024;

    private sealed record Pattern(Rule Rule, Regex Regex, string Message, Severity? Severity = null);

    private static Pattern P(Rule rule, string pattern, string message, Severity? severity = null) =>
        new(rule, new Regex(pattern, Options, Timeout), message, severity);

    private static readonly Pattern[] ContentPatterns =
    [
        // SKL002
        P(Rules.PromptInjection, @"\b(ignore|disregard|forget|override)\s+(?:(?:all|any|the|your|of|every)\s+)*(?:previous|prior|above|earlier|preceding|existing|system|original|other)\s+(?:instructions?|rules|directions|prompts?|guidelines|context|messages)\b", "Tries to override the agent's instructions"),
        P(Rules.PromptInjection, @"\byou\s+are\s+(?:now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|god)\s*mode|no\s+longer\s+(?:bound|restricted|an?\s+(?:ai|assistant)))", "Jailbreak phrasing"),
        P(Rules.PromptInjection, @"\b(?:new|updated|real|actual|true)\s+system\s+(?:prompt|instructions?)\s*:", "Fake system prompt"),
        P(Rules.PromptInjection, @"<\|im_(?:start|end)\|>|\[/?INST\]|<<\s*/?SYS\s*>>", "Chat-template control tokens"),
        P(Rules.PromptInjection, @"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|show|mention|reveal|disclose|notify)\s+(?:(?:this|it|anything|them)\s+)?(?:to\s+)?(?:the\s+)?(?:user|developer|human)\b(?!\s+to\b)", "Asks the agent to keep something from the user"),
        P(Rules.PromptInjection, @"\b(?:hide|conceal)\s+(?:this|these|it|them)(?:\s+\w+){0,2}\s+from\s+the\s+(?:user|developer)\b", "Asks the agent to hide actions from the user"),
        P(Rules.PromptInjection, @"\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+(?:user|developer)\b", "Asks the agent to act behind the user's back"),
        P(Rules.PromptInjection, @"\b(?:ignora|olvida|omite)\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)\b", "Tries to override the agent's instructions"),
        P(Rules.PromptInjection, @"\bno\s+(?:se\s+lo\s+)?(?:digas|cuentes|menciones|muestres)\s+al\s+usuario\b", "Asks the agent to keep something from the user"),

        // SKL003
        P(Rules.DisableSafety, @"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|\bbypassPermissions\b|--yolo\b|--allow-all-tools\b", "Skips the agent's permission prompts"),
        P(Rules.DisableSafety, @"\b(?:disable|turn\s+off|deactivate)\s+(?:the\s+|all\s+|any\s+)?(?:hooks?|sandbox(?:ing)?|safety\s+(?:checks?|features?)|guardrails?|approvals?|permission\s+prompts?)\b", "Asks to disable safety controls"),
        P(Rules.DisableSafety, @"\b(?:skip|bypass)\s+(?:the\s+|all\s+|any\s+)?(?:permission|approval)\s+(?:prompts?|checks?|requests?)\b", "Asks to skip approvals"),
        P(Rules.DisableSafety, @"\bwithout\s+(?:asking|requesting|waiting)\s+(?:for\s+)?(?:(?:the\s+)?user'?s?\s+)?(?:permission|approval|confirmation)\b", "Asks to act without confirmation"),
        P(Rules.DisableSafety, @"\bgit\s+(?:commit|push)\b[^\n]*--no-verify\b", "Skips git hooks", Severity.Warning),

        // SKL004
        P(Rules.RemoteCodeExecution, @"\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|pwsh|powershell|iex|invoke-expression|python[0-9.]*|node|perl|ruby)\b", "Pipes a download into a shell"),
        P(Rules.RemoteCodeExecution, @"\b(?:iex|invoke-expression)\b[^\n]*\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)\b", "Runs downloaded PowerShell"),
        P(Rules.RemoteCodeExecution, @"\.DownloadString\s*\(", "Downloads code to run it"),
        P(Rules.RemoteCodeExecution, @"\b(?:bash|sh|zsh)\s+(?:-c\s+)?[""']?\s*<\(\s*(?:curl|wget)\b|\beval\s+[""']?\$\(\s*(?:curl|wget)\b", "Runs a downloaded script"),
        P(Rules.RemoteCodeExecution, @"\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|python[0-9.]*|perl)\b", "Decodes and runs a hidden script"),

        // SKL005
        P(Rules.UntrustedPackageSource, @"\bdotnet\s+nuget\s+add\s+source\b|\bnuget(?:\.exe)?\s+sources\s+add\b|--add-source\b", "Adds a NuGet feed"),
        P(Rules.UntrustedPackageSource, @"\b(?:dotnet|nuget(?:\.exe)?)\b[^\n]*(?:--source|\s-s)\s+[""']?https?://(?!api\.nuget\.org)", "Installs from a non-default feed"),
        P(Rules.UntrustedPackageSource, @"\bpip[0-9.]*\s+install\b[^\n]*(?:git\+|https?://)|--(?:extra-)?index-url\b", "Installs Python packages from a URL or another index"),
        P(Rules.UntrustedPackageSource, @"\b(?:npm|pnpm|yarn)\s+(?:i|install|add)\b[^\n]*(?:https?://|git(?:\+ssh)?://|github:)|--registry[= ][""']?https?://(?!registry\.npmjs\.org)", "Installs npm packages from a URL or another registry"),

        // SKL006
        P(Rules.PackageInstall, @"\b(?:npm|pnpm|yarn)\s+(?:i|install|add)\s+(?:(?:-g|--global|-D|--save-dev)\s+)?[@a-z][\w./@-]*|\bnpx\s+(?:(?:-y|--yes)\s+)?[@a-z][\w./@-]*", "Installs or runs npm packages"),
        P(Rules.PackageInstall, @"\bpip[0-9.]*\s+install\s+(?:(?:-U|--upgrade|--user)\s+)?[a-z][\w.\[\]-]*|\buvx?\s+(?:tool\s+install|pip\s+install)\s+[a-z][\w.-]*", "Installs Python packages"),
        P(Rules.PackageInstall, @"\bdotnet\s+tool\s+(?:install|exec)\s+(?:(?:-g|--global)\s+)?[\w.-]+|\bdnx\s+[a-z][\w.-]*|\bdotnet\s+(?:add\s+[^\n]*\bpackage|package\s+add)\s+[\w.-]+", "Installs .NET tools or packages"),
        P(Rules.PackageInstall, @"\b(?:brew|apt(?:-get)?|choco|winget|scoop|cargo|go)\s+install\b", "Installs system tools"),

        // SKL007
        P(Rules.SecretAccess, @"~/\.ssh\b|\.ssh[\\/](?:id_|authorized_keys|config)|\bid_(?:rsa|ed25519|ecdsa|dsa)\b", "Reads SSH keys"),
        P(Rules.SecretAccess, @"\.aws[\\/](?:credentials|config)\b|\.azure[\\/]|\.kube[\\/]config\b|\.docker[\\/]config\.json\b|\bGOOGLE_APPLICATION_CREDENTIALS\b", "Reads cloud credentials"),
        P(Rules.SecretAccess, @"(?:^|[\s/\\""'`(@=<])\.(?:npmrc|pypirc|netrc|git-credentials)\b|\bClearTextPassword\b|NuGet[\\/]NuGet\.Config\b", "Reads package or git credentials"),
        P(Rules.SecretAccess, @"(?:^|[\s/\\""'`(@=<])\.env(?:\.[a-z]+)?(?=$|[\s""'`),;:|>])", "Reads a .env file"),
        P(Rules.SecretAccess, @"\b(?:GITHUB_TOKEN|GH_TOKEN|NUGET_API_KEY|NUGET_AUTH_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AZURE_CLIENT_SECRET|AZURE_DEVOPS_EXT_PAT|SYSTEM_ACCESSTOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SSH_AUTH_SOCK)\b", "Uses a secret environment variable", Severity.Info),
        P(Rules.SecretAccess, @"\bprintenv\b|\b(?:Get-ChildItem|gci|dir|ls)\s+env:|\bsecurity\s+find-(?:generic|internet)-password\b|\bcmdkey\s+/list\b|\bgh\s+auth\s+token\b|\baz\s+account\s+get-access-token\b|\bgit\s+credential\s+fill\b", "Dumps credentials or environment variables"),
        P(Rules.SecretAccess, @"\b(?:Login\s+Data|cookies\.sqlite|Local\s+State)\b", "Reads browser credential stores"),

        // SKL009
        P(Rules.SuspiciousEndpoint, @"\b(?:webhook\.site|requestbin\.(?:com|net)|(?:[a-z0-9-]+\.)?pipedream\.(?:net|com)|(?:[a-z0-9-]+\.)?ngrok(?:-free)?\.(?:io|app|dev)|[a-z0-9-]+\.trycloudflare\.com|interact\.sh|[a-z0-9-]+\.oast\.(?:fun|live|me|pro|site|online)|burpcollaborator\.net|oastify\.com|canarytokens\.(?:com|org)|pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|0x0\.st|file\.io)\b", "Request-capture, tunnel or paste service"),
        P(Rules.SuspiciousEndpoint, @"\bdiscord(?:app)?\.com/api/webhooks\b|\bapi\.telegram\.org/bot", "Chat webhook"),
        P(Rules.SuspiciousEndpoint, @"\bhttps?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.))(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", "URL with a raw IP address"),

        // SKL010
        P(Rules.EncodedPayload, @"-(?:EncodedCommand|enc|e)\s+[A-Za-z0-9+/]{20,}={0,2}", "Encoded PowerShell command"),
        P(Rules.EncodedPayload, @"\bFromBase64String\s*\(|\batob\s*\(|\bbase64\s+(?:-d|--decode)\b|\bbase64\.b64decode\s*\(", "Decodes content at run time", Severity.Info),
        P(Rules.EncodedPayload, @"(?:\\x[0-9a-f]{2}){16,}|String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){10,}", "Escaped or char-coded payload"),

        // SKL011
        P(Rules.DestructiveCommand, @"\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\s+[""']?(?:/\*?|~/?|\$HOME/?|\$\{HOME\}/?|\*|\.)(?=[""'`\s;)]|$)", "Recursive delete of a root, home or current folder"),
        P(Rules.DestructiveCommand, @"^(?=[^\n]*\bRemove-Item\b)(?=[^\n]*-Recurse)[^\n]*\s[""']?(?:[A-Z]:\\?|~[\\/]?|\$HOME|\$env:USERPROFILE|\$env:HOMEPATH)[""']?(?=\s|$)", "Recursive delete of a drive or home folder"),
        P(Rules.DestructiveCommand, @"\bgit\s+push\b[^\n]*(?:--force(?!-with-lease)\b|\s-f\b)|\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*(?:fd|df)[a-z]*\b", "Rewrites or discards git history"),
        P(Rules.DestructiveCommand, @"\bformat\s+[a-z]:|\bmkfs(?:\.\w+)?\b|\bdd\s+[^\n]*of=/dev/|\bdel\s+/[sfq]\s+/[sfq]|\brd\s+/s\s+/q\s+[a-z]:\\", "Wipes a disk or drive"),
        P(Rules.DestructiveCommand, @"\bDROP\s+(?:DATABASE|SCHEMA|TABLE)\b|\bTRUNCATE\s+TABLE\b", "Drops database objects"),
        P(Rules.DestructiveCommand, @"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b|:\(\)\s*\{\s*:\|:&\s*\};:", "World-writable permissions or fork bomb"),
    ];

    private static readonly Regex NetworkSend = new(
        @"\bcurl\b[^\n]*(?:\s-d\b|\s--data(?:-binary|-raw|-urlencode)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|-X\s*POST\b|--request\s+POST\b)" +
        @"|\bwget\b[^\n]*--post-(?:data|file)\b" +
        @"|\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*(?:-Method\s+Post\b|-Body\b|-InFile\b)" +
        @"|\b(?:nc|ncat|netcat)\s+[^\n]*\b\d{2,5}\b|\brequests\.(?:post|put)\s*\(|\bfetch\s*\([^\n]*method\s*:\s*[""'](?:POST|PUT)|\.(?:PostAsync|PutAsync|UploadString|UploadFile)\s*\(|\bscp\s+[^\n]*\s[^\s@]+@[^\s:]+:",
        Options, Timeout);

    private static readonly Regex EnvironmentRead = new(
        @"\$env:|\bprocess\.env\b|\bos\.environ\b|\bEnvironment\.GetEnvironmentVariables?\b|\$\{?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PAT|PASS)\b|\benv\s*\|",
        Options, Timeout);

    private static readonly Regex HtmlComment = new(@"<!--([\s\S]*?)-->", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex LinkComment = new(@"^[ \t]*\[[^\]\n]*\]:[ \t]*#[ \t]*[(""']([^\n]+)[)""'][ \t]*$", RegexOptions.Multiline | RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex ToolingComment = new(@"^\s*/?\s*(?:markdownlint|prettier|toc|omit|vale|cspell|textlint|eslint|region|endregion|#region|#endregion|begin|end|start|stop|include|snippet|auto-generated|generated)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Base64Blob = new(@"[A-Za-z0-9+/]{160,}={0,2}", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex SkillName = new(@"^[a-z0-9](?:[a-z0-9]|-(?!-)){0,63}$", RegexOptions.CultureInvariant);

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".msi", ".jar", ".class", ".pyc", ".wasm", ".node", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".nupkg" };
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".csx" };
    private static readonly HashSet<string> MediaExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz", ".woff", ".woff2", ".ttf", ".otf", ".pdf" };

    private static readonly HashSet<string> BroadTools = new(StringComparer.OrdinalIgnoreCase)
        { "*", "all", "Bash", "Bash(*)", "Bash(*:*)", "PowerShell", "PowerShell(*)", "Shell", "Shell(*)", "shell(*)", "run_in_terminal", "Execute", "Computer" };

    public static List<Finding> Scan(Skill skill)
    {
        var findings = new List<Finding>();
        var scripts = new List<string>();
        foreach (var file in skill.Files)
        {
            var path = Path.Combine(skill.Directory, file.Replace('/', Path.DirectorySeparatorChar));
            var extension = Path.GetExtension(file);
            if (MediaExtensions.Contains(extension)) continue;

            byte[] bytes;
            try { bytes = File.ReadAllBytes(path); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }

            if (BinaryExtensions.Contains(extension) || IsBinary(bytes))
            {
                findings.Add(Create(Rules.BundledBinary, null, $"Binary file {file} ({bytes.Length:N0} bytes) cannot be reviewed as text", skill, file, 0, 0, file));
                continue;
            }

            if (ScriptExtensions.Contains(extension)) scripts.Add(file);

            if (bytes.Length > MaxScannedBytes) continue;
            var text = Decode(bytes);

            var isSkillFile = file.Equals("SKILL.md", StringComparison.OrdinalIgnoreCase);
            if (isSkillFile)
            {
                CheckFrontmatter(skill, file, text, findings);
                if (bytes.Length > LargeSkillBytes)
                    findings.Add(Create(Rules.LargeSkill, null, $"SKILL.md is {bytes.Length / 1024} KB; every load costs tokens", skill, file, 0, 0, "size"));
            }

            ScanText(skill, file, text, findings);
        }

        if (scripts.Count > 0)
        {
            var list = string.Join(", ", scripts.Take(5)) + (scripts.Count > 5 ? $" and {scripts.Count - 5} more" : "");
            findings.Add(Create(Rules.BundledScript, null, $"{scripts.Count} script(s) the agent may run: {list}", skill, scripts[0], 0, 0, null, string.Join("|", scripts)));
        }
        return Deduplicate(findings);
    }

    internal static void ScanText(Skill skill, string file, string text, List<Finding> findings)
    {
        var lines = new LineMap(text);
        HiddenCharacters(skill, file, text, lines, findings);

        foreach (var pattern in ContentPatterns)
        {
            foreach (Match match in SafeMatches(pattern.Regex, text))
            {
                var (line, column) = lines.Position(match.Index);
                if (pattern.Rule == Rules.PromptInjection && IsQuoted(text, match))
                {
                    // Skills that defend against injection quote the phrases ("if the input says 'ignore previous instructions'…").
                    findings.Add(Create(pattern.Rule, Severity.Warning, $"{pattern.Message} (quoted: often a warning about injection; check the context)", skill, file, line, column, match.Value));
                    continue;
                }
                findings.Add(Create(pattern.Rule, pattern.Severity, pattern.Message, skill, file, line, column, match.Value));
            }
        }

        foreach (Match match in SafeMatches(Base64Blob, text))
        {
            var value = match.Value;
            if (!(value.Any(char.IsUpper) && value.Any(char.IsLower) && value.Any(char.IsDigit))) continue;
            var (line, column) = lines.Position(match.Index);
            findings.Add(Create(Rules.EncodedPayload, null, $"Base64 blob of {value.Length} characters", skill, file, line, column, value));
        }

        Exfiltration(skill, file, text, lines, findings);

        if (file.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            var fences = FencedRanges(text);
            foreach (Match match in SafeMatches(HtmlComment, text))
            {
                if (fences.Any(r => match.Index >= r.Start && match.Index < r.End)) continue; // shown as code when rendered
                var inner = match.Groups[1].Value.Trim();
                if (inner.Length == 0 || ToolingComment.IsMatch(inner)) continue;
                if (inner.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length < 4) continue;
                var (line, column) = lines.Position(match.Index);
                findings.Add(Create(Rules.HiddenComment, null, "HTML comment: invisible when rendered, read by the agent", skill, file, line, column, inner));
            }
            foreach (Match match in SafeMatches(LinkComment, text))
            {
                var (line, column) = lines.Position(match.Index);
                findings.Add(Create(Rules.HiddenComment, null, "Markdown link-reference comment: invisible when rendered, read by the agent", skill, file, line, column, match.Groups[1].Value));
            }
        }
    }

    /// <summary>A network send within three lines of a secret or environment read.</summary>
    private static void Exfiltration(Skill skill, string file, string text, LineMap lines, List<Finding> findings)
    {
        var secretLines = new HashSet<int>();
        foreach (var pattern in ContentPatterns.Where(p => p.Rule == Rules.SecretAccess))
            foreach (Match match in SafeMatches(pattern.Regex, text))
                secretLines.Add(lines.Position(match.Index).Line);
        foreach (Match match in SafeMatches(EnvironmentRead, text))
            secretLines.Add(lines.Position(match.Index).Line);
        if (secretLines.Count == 0) return;

        foreach (Match match in SafeMatches(NetworkSend, text))
        {
            var (line, column) = lines.Position(match.Index);
            if (secretLines.Any(s => Math.Abs(s - line) <= 3))
                findings.Add(Create(Rules.DataExfiltration, null, "Sends data over the network next to secrets or environment variables", skill, file, line, column, lines.LineText(line)));
        }
    }

    private static void HiddenCharacters(Skill skill, string file, string text, LineMap lines, List<Finding> findings)
    {
        var reported = new HashSet<int>();
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            int codePoint = c;
            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                codePoint = char.ConvertToUtf32(c, text[i + 1]);

            if (!IsHidden(codePoint, text, i)) continue;

            var (line, column) = lines.Position(i);
            if (!reported.Add(line)) { if (codePoint > 0xFFFF) i++; continue; }

            // Unicode tag characters map 1:1 to ASCII: decode the hidden text so the reviewer can read it.
            var decoded = new StringBuilder();
            var kinds = new SortedSet<string>(StringComparer.Ordinal);
            for (var j = i; j < text.Length && text[j] != '\n'; j++)
            {
                int cp = text[j];
                if (char.IsHighSurrogate(text[j]) && j + 1 < text.Length && char.IsLowSurrogate(text[j + 1])) cp = char.ConvertToUtf32(text[j], text[j + 1]);
                if (IsHidden(cp, text, j))
                {
                    kinds.Add($"U+{cp:X4}");
                    if (cp is >= 0xE0020 and <= 0xE007E) decoded.Append((char)(cp - 0xE0000));
                }
                if (cp > 0xFFFF) j++;
            }

            var message = decoded.Length > 0
                ? $"Invisible Unicode tag characters spell out hidden text: \"{Truncate(decoded.ToString(), 160)}\""
                : $"Invisible characters ({string.Join(", ", kinds.Take(6))}{(kinds.Count > 6 ? ", …" : "")})";
            findings.Add(Create(Rules.HiddenUnicode, null, message, skill, file, line, column, CollapseHidden(lines.LineText(line)), lines.LineText(line)));
            if (codePoint > 0xFFFF) i++;
        }
    }

    private static bool IsHidden(int codePoint, string text, int index) => codePoint switch
    {
        0xFEFF => index != 0,                                  // BOM is fine at the start
        0x200D => !(index > 0 && (char.IsLowSurrogate(text[index - 1]) || text[index - 1] is '️')), // ZWJ inside emoji
        0x200B or 0x200C or 0x200E or 0x200F => true,          // zero-width space/non-joiner, LRM/RLM
        >= 0x202A and <= 0x202E => true,                       // bidi embeddings and overrides
        >= 0x2060 and <= 0x2064 => true,                       // word joiner, invisible operators
        >= 0x2066 and <= 0x2069 => true,                       // bidi isolates
        0x00AD or 0x180E or 0x115F or 0x1160 or 0x3164 or 0xFFA0 => true, // soft hyphen, Mongolian vowel separator, Hangul fillers
        >= 0xE0000 and <= 0xE007F => true,                     // Unicode tags (ASCII smuggling)
        >= 0xFE00 and <= 0xFE0E => false,
        _ => false,
    };

    private static void CheckFrontmatter(Skill skill, string file, string text, List<Finding> findings)
    {
        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        var frontmatter = Frontmatter.Parse(lines);

        if (!frontmatter.Present || !frontmatter.Closed)
        {
            findings.Add(Create(Rules.InvalidFrontmatter, null, frontmatter.Present ? "Frontmatter is not closed with ---" : "SKILL.md has no YAML frontmatter", skill, file, 1, 1, "frontmatter"));
            return;
        }

        var name = frontmatter.Get("name");
        skill.DeclaredName = string.IsNullOrWhiteSpace(name) ? null : name;
        if (string.IsNullOrWhiteSpace(name))
            findings.Add(Create(Rules.InvalidFrontmatter, null, "Frontmatter has no name", skill, file, 1, 1, "name"));
        else
        {
            if (!SkillName.IsMatch(name) || name.EndsWith('-'))
                findings.Add(Create(Rules.InvalidFrontmatter, Severity.Info, $"Name \"{name}\" is not lowercase letters, digits and single hyphens (max 64)", skill, file, frontmatter.KeyLines["name"], 1, "name-format"));
            if (!string.Equals(name, skill.FolderName, StringComparison.Ordinal))
                findings.Add(Create(Rules.NameMismatch, null, $"Name \"{name}\" does not match the folder \"{skill.FolderName}\"", skill, file, frontmatter.KeyLines["name"], 1, "name"));
        }

        var description = frontmatter.Get("description");
        if (string.IsNullOrWhiteSpace(description))
            findings.Add(Create(Rules.InvalidFrontmatter, null, "Frontmatter has no description", skill, file, 1, 1, "description"));
        else if (description.Length > 1024)
            findings.Add(Create(Rules.DescriptionTooLong, null, $"Description has {description.Length} characters", skill, file, frontmatter.KeyLines["description"], 1, "description"));

        foreach (var (key, line) in frontmatter.DuplicateKeys)
            findings.Add(Create(Rules.InvalidFrontmatter, null, $"Duplicate key \"{key}\": a reviewer may read one value while the agent uses the other", skill, file, line, 1, key));

        foreach (var key in new[] { "allowed-tools", "allowed_tools", "tools" })
        {
            if (!frontmatter.KeyLines.TryGetValue(key, out var line)) continue;
            foreach (var tool in frontmatter.GetList(key).Where(BroadTools.Contains))
                findings.Add(Create(Rules.BroadToolGrant, null, $"{key} grants \"{tool}\" without restrictions", skill, file, line, 1, tool));
        }
    }

    internal static Finding Create(Rule rule, Severity? severity, string message, Skill? skill, string? file, int line, int column, string? evidence, string? fingerprintKey = null)
    {
        var shown = evidence is null ? null : Truncate(Visible(evidence.Trim()), 120);
        var normalized = Regex.Replace(fingerprintKey ?? evidence ?? "", @"\s+", " ").Trim().ToLowerInvariant();
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{rule.Id}|{file}|{normalized}")))[..16].ToLowerInvariant();
        return new Finding(rule, severity ?? rule.Severity, message, skill, file, line, column, shown) { Fingerprint = fingerprint };
    }

    /// <summary>One finding per line; info findings once per file (a skill that says "npx playwright" 100 times is one note).</summary>
    private static List<Finding> Deduplicate(List<Finding> findings) =>
        findings
            .GroupBy(f => (f.Rule.Id, f.File, Line: f.Severity == Severity.Info ? 0 : f.Line, f.Fingerprint))
            .Select(g => g.OrderByDescending(f => f.Severity).First())
            // Exfiltration explains the secret access on the same line better than two findings.
            .Where(f => f.Rule != Rules.SecretAccess || !findings.Any(e => e.Rule == Rules.DataExfiltration && e.File == f.File && e.Line == f.Line))
            .OrderBy(f => f.File, StringComparer.Ordinal).ThenBy(f => f.Line).ThenBy(f => f.Rule.Id, StringComparer.Ordinal)
            .ToList();

    private static IEnumerable<Match> SafeMatches(Regex regex, string text)
    {
        try { return regex.Matches(text).ToList(); }
        catch (RegexMatchTimeoutException) { return []; }
    }

    private static bool IsBinary(byte[] bytes)
    {
        if (bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF))) return false; // UTF-16 text
        var length = Math.Min(bytes.Length, 8192);
        for (var i = 0; i < length; i++) if (bytes[i] == 0) return true;
        return false;
    }

    private static string Decode(byte[] bytes)
    {
        using var reader = new StreamReader(new MemoryStream(bytes), new UTF8Encoding(false), detectEncodingFromByteOrderMarks: true);
        var text = reader.ReadToEnd();
        // Keep a leading BOM visible to IsHidden's "index 0" rule only if it survived decoding (it doesn't for UTF-8).
        return text;
    }

    internal static string Visible(string text)
    {
        var builder = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            int cp = text[i];
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1])) cp = char.ConvertToUtf32(text[i], text[i + 1]);
            if (IsHidden(cp, text, i) || (cp < 0x20 && cp != '\t')) builder.Append($"<U+{cp:X4}>");
            else if (cp > 0xFFFF) builder.Append(text, i, 2);
            else builder.Append(text[i]);
            if (cp > 0xFFFF) i++;
        }
        return builder.ToString();
    }

    private const string OpenQuotes = "\"'`“‘«„";
    private const string CloseQuotes = "\"'`”’»“";

    private static bool IsQuoted(string text, Match match)
    {
        var before = match.Index - 1;
        while (before >= 0 && text[before] is ' ' or '\t') before--;
        if (before < 0 || !OpenQuotes.Contains(text[before])) return false;
        var after = match.Index + match.Length;
        for (var i = after; i < Math.Min(text.Length, after + 3); i++)
            if (CloseQuotes.Contains(text[i])) return true;
        return false;
    }

    /// <summary>Character ranges of fenced code blocks (``` or ~~~).</summary>
    private static List<(int Start, int End)> FencedRanges(string text)
    {
        var ranges = new List<(int, int)>();
        int? open = null;
        string? fence = null;
        var index = 0;
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimStart();
            if (open is null && (trimmed.StartsWith("```", StringComparison.Ordinal) || trimmed.StartsWith("~~~", StringComparison.Ordinal)))
            {
                open = index;
                fence = trimmed[..3];
            }
            else if (open is not null && trimmed.StartsWith(fence!, StringComparison.Ordinal))
            {
                ranges.Add((open.Value, index + line.Length));
                open = null;
            }
            index += line.Length + 1;
        }
        if (open is not null) ranges.Add((open.Value, text.Length));
        return ranges;
    }

    /// <summary>The line as a reviewer sees it, with each run of invisible characters marked.</summary>
    private static string CollapseHidden(string line)
    {
        var builder = new StringBuilder();
        var run = 0;
        for (var i = 0; i < line.Length; i++)
        {
            int cp = line[i];
            var pair = char.IsHighSurrogate(line[i]) && i + 1 < line.Length && char.IsLowSurrogate(line[i + 1]);
            if (pair) cp = char.ConvertToUtf32(line[i], line[i + 1]);
            if (IsHidden(cp, line, i)) run++;
            else
            {
                if (run > 0) { builder.Append($"⟦{run} hidden⟧"); run = 0; }
                builder.Append(line, i, pair ? 2 : 1);
            }
            if (pair) i++;
        }
        if (run > 0) builder.Append($"⟦{run} hidden⟧");
        return builder.ToString();
    }

    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";

    private sealed class LineMap
    {
        private readonly string _text;
        private readonly List<int> _starts = [0];

        public LineMap(string text)
        {
            _text = text;
            for (var i = 0; i < text.Length; i++) if (text[i] == '\n') _starts.Add(i + 1);
        }

        public (int Line, int Column) Position(int index)
        {
            var line = _starts.BinarySearch(index);
            if (line < 0) line = ~line - 1;
            return (line + 1, index - _starts[line] + 1);
        }

        public string LineText(int line)
        {
            var start = _starts[line - 1];
            var end = line < _starts.Count ? _starts[line] - 1 : _text.Length;
            return _text[start..end].TrimEnd('\r');
        }
    }
}
