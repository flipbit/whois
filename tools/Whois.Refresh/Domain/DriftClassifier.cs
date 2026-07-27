namespace Whois.Refresh.Domain;

public enum DriftClassification
{
    NoMatch,
    FieldRegression,
    TemplateShift,
    StatusMismatch,
    NewEntry,
    QueryError,
}

public enum DriftSeverity
{
    Breakage,
    Drift,
    Info,
    Warning,
}

public record DriftEntry(
    string Server,
    string Tld,
    string Status,
    string Domain,
    DriftClassification Classification,
    DriftSeverity Severity,
    string Details,
    string? PreviousTemplate,
    string? CurrentTemplate,
    IList<string> PreviousFields,
    IList<string> CurrentFields);

public static class DriftClassifier
{
    public static IList<DriftEntry> Classify(
        RefreshResults baseline,
        RefreshResults current)
    {
        List<DriftEntry> entries = [];

        foreach (var (server, tlds) in current.Results)
        {
            foreach (var (tld, statuses) in tlds)
            {
                foreach (var (status, domains) in statuses)
                {
                    foreach (var (domain, currentResult) in domains)
                    {
                        var baselineResult = GetBaselineResult(baseline, server, tld, domain);

                        var entry = ClassifyDomain(
                            server, tld, status, domain,
                            baselineResult, currentResult);

                        if (entry != null)
                        {
                            entries.Add(entry);
                        }
                    }
                }
            }
        }

        return entries;
    }

    private static DriftEntry? ClassifyDomain(
        string server, string tld, string status, string domain,
        DomainResult? baselineResult, DomainResult currentResult)
    {
        // Query error (non-parse failures are transient and not breakages)
        if (currentResult.Error != null && currentResult.Error.Type != QueryErrorType.ParseFailure)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.QueryError, DriftSeverity.Warning,
                $"Query failed: {currentResult.Error.Type} — {currentResult.Error.Message}",
                baselineResult?.MatchedTemplate, null,
                baselineResult?.ExtractedFields ?? [], []);
        }

        // No baseline — new entry
        if (baselineResult == null)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.NewEntry, DriftSeverity.Info,
                "New domain, no baseline to compare",
                null, currentResult.MatchedTemplate,
                [], currentResult.ExtractedFields);
        }

        // Status mismatch (ActualStatus set by WhoisRefreshEngine when parsed status differs from expected)
        if (currentResult.ActualStatus != null && !string.Equals(currentResult.ActualStatus, status, StringComparison.OrdinalIgnoreCase))
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.StatusMismatch, DriftSeverity.Drift,
                $"Expected status '{status}', got '{currentResult.ActualStatus}'",
                baselineResult.MatchedTemplate, currentResult.MatchedTemplate,
                baselineResult.ExtractedFields, currentResult.ExtractedFields);
        }

        // No match (previously matched, now doesn't)
        if (baselineResult.MatchedTemplate != null && currentResult.MatchedTemplate == null)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.NoMatch, DriftSeverity.Breakage,
                $"Previously matched {baselineResult.MatchedTemplate}, now matches nothing",
                baselineResult.MatchedTemplate, null,
                baselineResult.ExtractedFields, []);
        }

        // Field regression
        if (currentResult.ExtractedFields.Count < baselineResult.ExtractedFields.Count)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.FieldRegression, DriftSeverity.Breakage,
                string.Format(System.Globalization.CultureInfo.InvariantCulture, "Fields reduced from {0} to {1}", baselineResult.ExtractedFields.Count, currentResult.ExtractedFields.Count),
                baselineResult.MatchedTemplate, currentResult.MatchedTemplate,
                baselineResult.ExtractedFields, currentResult.ExtractedFields);
        }

        // Template shift (different template, same or better fields)
        if (!string.Equals(currentResult.MatchedTemplate, baselineResult.MatchedTemplate, StringComparison.Ordinal))
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.TemplateShift, DriftSeverity.Info,
                $"Template changed from {baselineResult.MatchedTemplate} to {currentResult.MatchedTemplate}",
                baselineResult.MatchedTemplate, currentResult.MatchedTemplate,
                baselineResult.ExtractedFields, currentResult.ExtractedFields);
        }

        // No change
        return null;
    }

    private static DomainResult? GetBaselineResult(
        RefreshResults baseline, string server, string tld, string domain)
    {
        if (!baseline.Results.TryGetValue(server, out var serverResults)) return null;
        if (!serverResults.TryGetValue(tld, out var tldResults)) return null;

        foreach (var (_, domains) in tldResults)
        {
            if (domains.TryGetValue(domain, out var result))
                return result;
        }

        return null;
    }
}
