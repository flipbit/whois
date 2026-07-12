using System.Globalization;
using System.Text.RegularExpressions;

namespace WhoisMigration;

public static partial class TemplateMapper
{
    [GeneratedRegex(@"set:\s*Status\s*=\s*(\w+)")]
    private static partial Regex StatusDirectivePattern();

    [GeneratedRegex(@"(?<!^)([A-Z])")]
    private static partial Regex PascalCaseBoundary();

    [GeneratedRegex(@"^(name:\s*).+$", RegexOptions.Multiline)]
    private static partial Regex NameDirectivePattern();

    public static string? ExtractName(string templateContent)
    {
        var match = NameDirectivePattern().Match(templateContent);
        if (!match.Success) return null;
        // Extract value after "name: "
        var line = match.Value;
        var colonIdx = line.IndexOf(':', StringComparison.Ordinal);
        return colonIdx >= 0 ? line[(colonIdx + 1)..].Trim() : null;
    }

    public static string ExtractStatus(string templateContent)
    {
        var match = StatusDirectivePattern().Match(templateContent);
        if (match.Success) return match.Groups[1].Value;
        throw new InvalidOperationException("Template missing 'set: Status = ...' directive in front matter");
    }

    public static string ToStatusDirectory(string pascalCaseStatus)
    {
        return PascalCaseBoundary().Replace(pascalCaseStatus, "-$1").ToLowerInvariant();
    }

    public static IDictionary<string, string> AssignNumbers(IList<string> filenames)
    {
        var sorted = filenames.Order(StringComparer.OrdinalIgnoreCase).ToList();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < sorted.Count; i++)
        {
            result[sorted[i]] = (i + 1).ToString("D2", CultureInfo.InvariantCulture);
        }
        return result;
    }

    public static string UpdateFrontMatterName(string content, string newName)
    {
        return NameDirectivePattern().Replace(content, $"${{1}}{newName}", 1);
    }
}
