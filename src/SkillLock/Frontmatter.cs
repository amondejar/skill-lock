namespace SkillLock;

/// <summary>
/// The YAML header of a SKILL.md. A deliberately small reader for the subset skills use
/// (scalars, quoted strings, folded or literal blocks and string lists), so the tool has no dependencies.
/// </summary>
public sealed class Frontmatter
{
    public bool Present { get; private init; }
    public bool Closed { get; private init; }
    public Dictionary<string, string> Values { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, List<string>> Lists { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, int> KeyLines { get; } = new(StringComparer.Ordinal);
    public List<(string Key, int Line)> DuplicateKeys { get; } = [];

    /// <summary>1-based line where the body starts.</summary>
    public int BodyStartLine { get; private init; } = 1;

    public string? Get(string key) => Values.TryGetValue(key, out var v) ? v : null;

    /// <summary>A key as a list: either a YAML list, an inline <c>[a, b]</c> list, or a space/comma-separated scalar.</summary>
    public IReadOnlyList<string> GetList(string key)
    {
        if (Lists.TryGetValue(key, out var list)) return list;
        var value = Get(key);
        if (string.IsNullOrWhiteSpace(value)) return [];
        value = value.Trim();
        if (value.StartsWith('[') && value.EndsWith(']')) value = value[1..^1];
        return SplitTools(value);
    }

    /// <summary>Splits on commas or spaces, but not inside parentheses (<c>Bash(git status:*)</c> is one item).</summary>
    private static List<string> SplitTools(string value)
    {
        var items = new List<string>();
        var depth = 0;
        var current = new System.Text.StringBuilder();
        foreach (var c in value)
        {
            if (c == '(') depth++;
            if (c == ')') depth = Math.Max(0, depth - 1);
            if (depth == 0 && (c == ',' || char.IsWhiteSpace(c)))
            {
                if (current.Length > 0) items.Add(Unquote(current.ToString()));
                current.Clear();
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0) items.Add(Unquote(current.ToString()));
        return items;
    }

    public static Frontmatter Parse(string[] lines)
    {
        if (lines.Length == 0 || lines[0].TrimEnd() != "---") return new Frontmatter();

        var end = Array.FindIndex(lines, 1, l => l.TrimEnd() is "---" or "...");
        var result = new Frontmatter { Present = true, Closed = end > 0, BodyStartLine = end > 0 ? end + 2 : 1 };
        if (end < 0) return result;

        string? listKey = null;
        for (var i = 1; i < end; i++)
        {
            var line = lines[i];
            if (line.Trim().Length == 0 || line.TrimStart().StartsWith('#')) continue;

            // "- item" under a key that had no inline value.
            if (listKey is not null && line.TrimStart().StartsWith("- ", StringComparison.Ordinal))
            {
                result.Lists[listKey].Add(Unquote(line.TrimStart()[2..].Trim()));
                continue;
            }

            if (char.IsWhiteSpace(line[0])) continue; // nested mapping we don't need (e.g. metadata:)
            listKey = null;

            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (result.KeyLines.ContainsKey(key)) result.DuplicateKeys.Add((key, i + 1));
            else result.KeyLines[key] = i + 1;

            if (value is ">" or ">-" or ">+" or "|" or "|-" or "|+")
            {
                var folded = value.StartsWith('>');
                var block = new List<string>();
                while (i + 1 < end && (lines[i + 1].Length == 0 || char.IsWhiteSpace(lines[i + 1][0])))
                {
                    i++;
                    block.Add(lines[i].Trim());
                }
                result.Values[key] = folded
                    ? string.Join(" ", block.Where(b => b.Length > 0))
                    : string.Join("\n", block).Trim('\n');
                continue;
            }

            if (value.Length == 0)
            {
                listKey = key;
                result.Lists[key] = [];
                result.Values[key] = "";
                continue;
            }

            result.Values[key] = Unquote(value);
        }

        // Keys with an empty value and no list items are plain empty values.
        foreach (var key in result.Lists.Where(l => l.Value.Count == 0).Select(l => l.Key).ToList())
            result.Lists.Remove(key);
        return result;
    }

    private static string Unquote(string value)
    {
        value = value.Trim();
        if (value.Length >= 2 && ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            return value[1..^1];
        return value;
    }
}
