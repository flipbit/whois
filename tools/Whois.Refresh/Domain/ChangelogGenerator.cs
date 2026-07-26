using System.Text;
using System.Text.Json;
using Whois.Templates;

namespace Whois.Refresh.Domain;

public sealed class ChangelogResult
{
    public IList<string> Added { get; init; } = new List<string>();
    public IList<string> Removed { get; init; } = new List<string>();
    public IList<string> Modified { get; init; } = new List<string>();
    public bool HasChanges => Added.Count > 0 || Removed.Count > 0 || Modified.Count > 0;

    public string ToJson()
    {
        return JsonSerializer.Serialize(new
        {
            added = Added,
            removed = Removed,
            modified = Modified,
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    public string ToMarkdown()
    {
        if (!HasChanges)
            return "No changes detected.\n";

        var sb = new StringBuilder();
        sb.AppendLine("# Template Changelog");
        sb.AppendLine();

        if (Added.Count > 0)
        {
            sb.AppendLine("## Added");
            sb.AppendLine();
            foreach (var path in Added)
                sb.AppendLine($"- `{path}`");
            sb.AppendLine();
        }

        if (Removed.Count > 0)
        {
            sb.AppendLine("## Removed");
            sb.AppendLine();
            foreach (var path in Removed)
                sb.AppendLine($"- `{path}`");
            sb.AppendLine();
        }

        if (Modified.Count > 0)
        {
            sb.AppendLine("## Modified");
            sb.AppendLine();
            foreach (var path in Modified)
                sb.AppendLine($"- `{path}`");
            sb.AppendLine();
        }

        return sb.ToString();
    }
}

public static class ChangelogGenerator
{
    /// <summary>
    /// Diffs two manifests by comparing per-template hashes.
    /// </summary>
    /// <param name="current">The new manifest.</param>
    /// <param name="previous">The previous manifest, or null for a first release.</param>
    public static ChangelogResult Generate(TemplateManifest current, TemplateManifest? previous)
    {
        var currentMap = current.Templates.ToDictionary(t => t.Path, t => t.Hash, StringComparer.Ordinal);
        var previousMap = previous?.Templates.ToDictionary(t => t.Path, t => t.Hash, StringComparer.Ordinal)
            ?? new Dictionary<string, string>(StringComparer.Ordinal);

        var added = new List<string>();
        var removed = new List<string>();
        var modified = new List<string>();

        foreach (var (path, hash) in currentMap)
        {
            if (!previousMap.TryGetValue(path, out var prevHash))
                added.Add(path);
            else if (!string.Equals(hash, prevHash, StringComparison.Ordinal))
                modified.Add(path);
        }

        foreach (var path in previousMap.Keys)
        {
            if (!currentMap.ContainsKey(path))
                removed.Add(path);
        }

        added.Sort(StringComparer.Ordinal);
        removed.Sort(StringComparer.Ordinal);
        modified.Sort(StringComparer.Ordinal);

        return new ChangelogResult
        {
            Added = added,
            Removed = removed,
            Modified = modified,
        };
    }
}
