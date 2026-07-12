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

    public static Dictionary<string, string> AssignNumbers(List<string> filenames)
    {
        var sorted = filenames.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
        var result = new Dictionary<string, string>();
        for (var i = 0; i < sorted.Count; i++)
        {
            result[sorted[i]] = (i + 1).ToString("D2");
        }
        return result;
    }

    public static string UpdateFrontMatterName(string content, string newName)
    {
        return NameDirectivePattern().Replace(content, $"${{1}}{newName}", 1);
    }
}
