namespace SkillLock;

public sealed record Rule(string Id, string Name, Severity Severity, string Title, string Description)
{
    public string HelpUri => $"https://github.com/amondejar/skill-lock/blob/main/docs/rules.md#{Id.ToLowerInvariant()}";
}

/// <summary>Every check SkillLock runs. IDs are stable: suppressions and SARIF baselines depend on them.</summary>
public static class Rules
{
    // Content: things a skill tells the agent to do.
    public static readonly Rule HiddenUnicode = new("SKL001", "HiddenUnicode", Severity.Error,
        "Invisible or bidirectional Unicode characters",
        "Zero-width, bidirectional-override and Unicode tag characters are invisible to reviewers but read by the model. They are the usual way to hide instructions in plain sight.");

    public static readonly Rule PromptInjection = new("SKL002", "PromptInjection", Severity.Error,
        "Instruction override or prompt injection",
        "Phrases that try to replace the agent's instructions (\"ignore previous instructions\", fake system prompts) or keep the user in the dark (\"do not tell the user\").");

    public static readonly Rule DisableSafety = new("SKL003", "DisableSafety", Severity.Error,
        "Turns off the agent's safety controls",
        "Asks the agent to skip permission prompts, disable hooks or sandboxing, or act without confirmation.");

    public static readonly Rule RemoteCodeExecution = new("SKL004", "RemoteCodeExecution", Severity.Error,
        "Downloads and runs code",
        "Pipes a download into a shell or interpreter (curl | bash, iwr | iex, DownloadString). Whatever the server returns runs on the developer's machine.");

    public static readonly Rule UntrustedPackageSource = new("SKL005", "UntrustedPackageSource", Severity.Warning,
        "Installs packages from a non-default source",
        "Adds a package feed or installs from a URL or git repository. A common way to slip a malicious dependency past review.");

    public static readonly Rule PackageInstall = new("SKL006", "PackageInstall", Severity.Info,
        "Asks the agent to install packages or tools",
        "Legitimate in many skills, but worth a look: check that the package names are the ones you expect (typosquatting).");

    public static readonly Rule SecretAccess = new("SKL007", "SecretAccess", Severity.Warning,
        "Reads credentials or secrets",
        "Mentions SSH keys, cloud credentials, .env files, NuGet or npm credentials, or token environment variables.");

    public static readonly Rule DataExfiltration = new("SKL008", "DataExfiltration", Severity.Error,
        "Sends secrets over the network",
        "An outbound request close to credentials or environment variables, or a known request-capture endpoint.");

    public static readonly Rule SuspiciousEndpoint = new("SKL009", "SuspiciousEndpoint", Severity.Warning,
        "Contacts a suspicious endpoint",
        "Request bins, tunnels, paste sites, chat webhooks or raw IP addresses. Rarely needed by a legitimate skill.");

    public static readonly Rule EncodedPayload = new("SKL010", "EncodedPayload", Severity.Warning,
        "Encoded or obfuscated content",
        "Long base64 blobs, encoded PowerShell commands or runtime decoding. Hides what will actually run.");

    public static readonly Rule DestructiveCommand = new("SKL011", "DestructiveCommand", Severity.Warning,
        "Destructive command",
        "Recursive deletes of home or root, force pushes, hard resets, dropping databases, world-writable permissions.");

    public static readonly Rule HiddenComment = new("SKL012", "HiddenComment", Severity.Warning,
        "Text hidden in an HTML comment",
        "HTML comments do not render on GitHub or in the IDE preview, but the agent reads them.");

    // Structure.
    public static readonly Rule BundledBinary = new("SKL013", "BundledBinary", Severity.Warning,
        "Binary file inside the skill",
        "Executables and libraries cannot be reviewed as text. A skill should not need them.");

    public static readonly Rule BundledScript = new("SKL014", "BundledScript", Severity.Info,
        "Script inside the skill",
        "Scripts are normal in skills, and the agent may run them. They are scanned with the same rules; review them like code.");

    public static readonly Rule BroadToolGrant = new("SKL015", "BroadToolGrant", Severity.Warning,
        "Grants unrestricted tools",
        "allowed-tools pre-approves tools for the skill. A wildcard or unrestricted shell lets the skill run anything without a prompt.");

    public static readonly Rule InvalidFrontmatter = new("SKL020", "InvalidFrontmatter", Severity.Warning,
        "Missing or invalid frontmatter",
        "SKILL.md must start with a YAML header with name and description (agentskills.io).");

    public static readonly Rule NameMismatch = new("SKL021", "NameMismatch", Severity.Info,
        "Name does not match the folder",
        "The specification expects the name field to match the skill's folder.");

    public static readonly Rule DescriptionTooLong = new("SKL022", "DescriptionTooLong", Severity.Info,
        "Description over 1024 characters",
        "The description is loaded into every conversation; the specification caps it at 1024 characters.");

    public static readonly Rule LargeSkill = new("SKL023", "LargeSkill", Severity.Info,
        "Large SKILL.md",
        "Every load costs tokens. Large skills are also harder to review.");

    public static readonly Rule NameCollision = new("SKL030", "NameCollision", Severity.Warning,
        "Two skills with the same name",
        "A package skill with the same name as another skill can shadow it: the agent may load the package's version instead of yours.");

    // Lock.
    public static readonly Rule NewSkill = new("SKL100", "NewSkill", Severity.Error,
        "Skill not in skills.lock.json",
        "A package (or someone) added a skill that nobody reviewed. Review it, then run skilllock lock.");

    public static readonly Rule ChangedSkill = new("SKL101", "ChangedSkill", Severity.Error,
        "Skill changed since it was locked",
        "The skill's files differ from the reviewed version, usually after a package update. Review the change, then run skilllock lock.");

    public static readonly Rule RemovedSkill = new("SKL102", "RemovedSkill", Severity.Info,
        "Locked skill no longer present",
        "Run skilllock lock to drop it from the lock file.");

    public static readonly Rule PackageNotRestored = new("SKL900", "PackageNotRestored", Severity.Warning,
        "Package could not be audited",
        "The package declares skills but its files are not in the packages folder, or the assets file could not be read.");

    public static readonly IReadOnlyList<Rule> All =
    [
        HiddenUnicode, PromptInjection, DisableSafety, RemoteCodeExecution, UntrustedPackageSource, PackageInstall,
        SecretAccess, DataExfiltration, SuspiciousEndpoint, EncodedPayload, DestructiveCommand, HiddenComment,
        BundledBinary, BundledScript, BroadToolGrant, InvalidFrontmatter, NameMismatch, DescriptionTooLong, LargeSkill,
        NameCollision, NewSkill, ChangedSkill, RemovedSkill, PackageNotRestored,
    ];
}
