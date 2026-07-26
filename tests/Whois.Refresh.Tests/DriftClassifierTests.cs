using Xunit;
using Whois.Refresh.Domain;

namespace Whois.Refresh.Tests;

public class DriftClassifierTests
{
    private static IDictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>> MakeResultsDict(
        string? template, IList<string> fields, QueryError? error = null)
    {
        return new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal)
        {
            ["whois.nic.uk"] = new Dictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>(StringComparer.Ordinal)
            {
                ["uk"] = new Dictionary<string, IDictionary<string, DomainResult>>(StringComparer.Ordinal)
                {
                    ["found"] = new Dictionary<string, DomainResult>(StringComparer.Ordinal)
                    {
                        ["google.co.uk"] = new DomainResult
                        {
                            Timestamp = DateTimeOffset.UtcNow,
                            MatchedTemplate = template,
                            ExtractedFields = fields,
                            Error = error,
                        },
                    },
                },
            },
        };
    }

    private static RefreshResults MakeResults(string? template, IList<string> fields, QueryError? error = null) =>
        new()
        {
            Version = DateTimeOffset.UtcNow,
            Results = MakeResultsDict(template, fields, error),
        };

    [Fact]
    public void Classify_NoMatch_WhenPreviouslyMatchedNowDoesNot()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults(null, []);

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NoMatch, entries[0].Classification);
        Assert.Equal(DriftSeverity.Breakage, entries[0].Severity);
    }

    [Fact]
    public void Classify_FieldRegression_WhenFewerFieldsExtracted()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar", "Expiration"]);
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName"]);

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.FieldRegression, entries[0].Classification);
        Assert.Equal(DriftSeverity.Breakage, entries[0].Severity);
    }

    [Fact]
    public void Classify_TemplateShift_WhenDifferentTemplateButEqualOrMoreFields()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults("whois.nic.uk/uk/found/02", ["DomainName", "Registrar", "Expiration"]);

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.TemplateShift, entries[0].Classification);
        Assert.Equal(DriftSeverity.Info, entries[0].Severity);
    }

    [Fact]
    public void Classify_StatusMismatch_WhenActualStatusDiffersFromExpected()
    {
        var current = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal)
            {
                ["whois.nic.uk"] = new Dictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>(StringComparer.Ordinal)
                {
                    ["uk"] = new Dictionary<string, IDictionary<string, DomainResult>>(StringComparer.Ordinal)
                    {
                        ["found"] = new Dictionary<string, DomainResult>(StringComparer.Ordinal)
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = "whois.nic.uk/uk/not-found/01",
                                ExtractedFields = ["DomainName"],
                                Error = null,
                                ActualStatus = "not-found",
                            },
                        },
                    },
                },
            },
        };
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Contains(entries, e => e.Classification == DriftClassification.StatusMismatch);
    }

    [Fact]
    public void Classify_NewEntry_WhenNoBaseline()
    {
        var baseline = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal),
        };
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NewEntry, entries[0].Classification);
        Assert.Equal(DriftSeverity.Info, entries[0].Severity);
    }

    [Fact]
    public void Classify_QueryError_RecordsWarning()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults(null, [], new QueryError
        {
            Type = QueryErrorType.Timeout,
            Message = "Timed out",
        });

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.QueryError, entries[0].Classification);
        Assert.Equal(DriftSeverity.Warning, entries[0].Severity);
    }

    [Fact]
    public void Classify_NoDrift_WhenResultsIdentical()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current);

        Assert.Empty(entries);
    }

    [Fact]
    public void ToMarkdown_GeneratesValidReport()
    {
        IList<DriftEntry> entries =
        [
            new("whois.nic.uk", "uk", "found", "google.co.uk",
                DriftClassification.NoMatch, DriftSeverity.Breakage,
                "Previously matched whois.nic.uk/uk/found/01, now matches nothing",
                "whois.nic.uk/uk/found/01", null, ["DomainName", "Registrar"], []),
        ];

        var markdown = DriftReportGenerator.ToMarkdown(entries);

        Assert.Contains("google.co.uk", markdown);
        Assert.Contains("Breakage", markdown);
        Assert.Contains("No match", markdown);
    }

    [Fact]
    public void ToJson_RoundTrips()
    {
        IList<DriftEntry> entries =
        [
            new("whois.nic.uk", "uk", "found", "google.co.uk",
                DriftClassification.FieldRegression, DriftSeverity.Breakage,
                "Fields reduced from 3 to 1",
                "whois.nic.uk/uk/found/01", "whois.nic.uk/uk/found/01",
                ["DomainName", "Registrar", "Expiration"], ["DomainName"]),
        ];

        var json = DriftReportGenerator.ToJson(entries);
        var deserialized = DriftReportGenerator.FromJson(json);

        Assert.Single(deserialized);
        Assert.Equal("google.co.uk", deserialized[0].Domain);
        Assert.Equal(DriftClassification.FieldRegression, deserialized[0].Classification);
    }
}
