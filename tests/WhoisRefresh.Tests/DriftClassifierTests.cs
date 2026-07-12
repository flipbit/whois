using Xunit;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Tests;

public class DriftClassifierTests
{
    private static DomainRegistryData SimpleRegistry(string server = "whois.nic.uk", string tld = "uk") =>
        new(new Dictionary<string, ServerEntry>
        {
            [server] = new(tld, false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

    private static RefreshResults MakeResults(string? template, List<string> fields, QueryError? error = null) =>
        new()
        {
            Version = DateTimeOffset.UtcNow,
            Results = new()
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = template,
                                ExtractedFields = fields,
                                Error = error
                            }
                        }
                    }
                }
            }
        };

    [Fact]
    public void Classify_NoMatch_WhenPreviouslyMatchedNowDoesNot()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults(null, []);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NoMatch, entries[0].Classification);
        Assert.Equal(DriftSeverity.Breakage, entries[0].Severity);
    }

    [Fact]
    public void Classify_FieldRegression_WhenFewerFieldsExtracted()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar", "Expiration"]);
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.FieldRegression, entries[0].Classification);
        Assert.Equal(DriftSeverity.Breakage, entries[0].Severity);
    }

    [Fact]
    public void Classify_TemplateShift_WhenDifferentTemplateButEqualOrMoreFields()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults("whois.nic.uk/uk/found/02", ["DomainName", "Registrar", "Expiration"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.TemplateShift, entries[0].Classification);
        Assert.Equal(DriftSeverity.Info, entries[0].Severity);
    }

    [Fact]
    public void Classify_StatusMismatch_WhenActualStatusDiffersFromExpected()
    {
        // Domain is listed under "found" in registry, result recorded under "found"
        // but ActualStatus shows it parsed as "not-found"
        var current = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new()
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = "whois.nic.uk/uk/not-found/01",
                                ExtractedFields = ["DomainName"],
                                Error = null,
                                ActualStatus = "not-found"
                            }
                        }
                    }
                }
            }
        };
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        // Registry says domain should be "found"
        var registry = SimpleRegistry();

        var entries = DriftClassifier.Classify(baseline, current, registry);

        Assert.Contains(entries, e => e.Classification == DriftClassification.StatusMismatch);
    }

    [Fact]
    public void Classify_NewEntry_WhenNoBaseline()
    {
        var baseline = new RefreshResults { Version = DateTimeOffset.UtcNow, Results = new() };
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

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
            Message = "Timed out"
        });

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.QueryError, entries[0].Classification);
        Assert.Equal(DriftSeverity.Warning, entries[0].Severity);
    }

    [Fact]
    public void Classify_NoDrift_WhenResultsIdentical()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Empty(entries);
    }

    [Fact]
    public void ToMarkdown_GeneratesValidReport()
    {
        var entries = new List<DriftEntry>
        {
            new("whois.nic.uk", "uk", "found", "google.co.uk",
                DriftClassification.NoMatch, DriftSeverity.Breakage,
                "Previously matched whois.nic.uk/uk/found/01, now matches nothing",
                "whois.nic.uk/uk/found/01", null, ["DomainName", "Registrar"], [])
        };

        var markdown = DriftReportGenerator.ToMarkdown(entries);

        Assert.Contains("google.co.uk", markdown);
        Assert.Contains("Breakage", markdown);
        Assert.Contains("No match", markdown);
    }

    [Fact]
    public void ToJson_RoundTrips()
    {
        var entries = new List<DriftEntry>
        {
            new("whois.nic.uk", "uk", "found", "google.co.uk",
                DriftClassification.FieldRegression, DriftSeverity.Breakage,
                "Fields reduced from 3 to 1",
                "whois.nic.uk/uk/found/01", "whois.nic.uk/uk/found/01",
                ["DomainName", "Registrar", "Expiration"], ["DomainName"])
        };

        var json = DriftReportGenerator.ToJson(entries);
        var deserialized = DriftReportGenerator.FromJson(json);

        Assert.Single(deserialized);
        Assert.Equal("google.co.uk", deserialized[0].Domain);
        Assert.Equal(DriftClassification.FieldRegression, deserialized[0].Classification);
    }
}
