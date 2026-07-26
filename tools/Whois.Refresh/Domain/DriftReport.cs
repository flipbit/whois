using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Whois.Refresh.Domain;

public static class DriftReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase), },
    };

    public static string ToJson(IList<DriftEntry> entries)
    {
        return JsonSerializer.Serialize(entries, JsonOptions);
    }

    public static IList<DriftEntry> FromJson(string json)
    {
        return JsonSerializer.Deserialize<List<DriftEntry>>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize drift entries");
    }

    public static string ToMarkdown(IList<DriftEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Drift Report");
        sb.AppendLine();

        var breakages = entries.Where(e => e.Severity == DriftSeverity.Breakage).ToList();
        var drift = entries.Where(e => e.Severity == DriftSeverity.Drift).ToList();
        var warnings = entries.Where(e => e.Severity == DriftSeverity.Warning).ToList();
        var info = entries.Where(e => e.Severity == DriftSeverity.Info).ToList();

        if (breakages.Count > 0)
        {
            sb.AppendLine("## Breakages");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in breakages)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        if (drift.Count > 0)
        {
            sb.AppendLine("## Drift");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in drift)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        if (warnings.Count > 0)
        {
            sb.AppendLine("## Warnings");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in warnings)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        if (info.Count > 0)
        {
            sb.AppendLine("## Informational");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in info)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string FormatClassification(DriftClassification classification) => classification switch
    {
        DriftClassification.NoMatch => "No match",
        DriftClassification.FieldRegression => "Field regression",
        DriftClassification.TemplateShift => "Template shift",
        DriftClassification.StatusMismatch => "Status mismatch",
        DriftClassification.NewEntry => "New entry",
        DriftClassification.QueryError => "Query error",
        _ => classification.ToString(),
    };
}
