using Xunit;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Tests;

public class RefreshResultTests
{
    private static IDictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>> MakeResults(
        string server, string tld, string status, string domain, DomainResult result)
    {
        return new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal)
        {
            [server] = new Dictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>(StringComparer.Ordinal)
            {
                [tld] = new Dictionary<string, IDictionary<string, DomainResult>>(StringComparer.Ordinal)
                {
                    [status] = new Dictionary<string, DomainResult>(StringComparer.Ordinal)
                    {
                        [domain] = result,
                    },
                },
            },
        };
    }

    private static IDictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>> MakeResultsTwoDomains(
        string server, string tld, string status, string domain1, DomainResult result1, string domain2, DomainResult result2)
    {
        return new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal)
        {
            [server] = new Dictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>(StringComparer.Ordinal)
            {
                [tld] = new Dictionary<string, IDictionary<string, DomainResult>>(StringComparer.Ordinal)
                {
                    [status] = new Dictionary<string, DomainResult>(StringComparer.Ordinal)
                    {
                        [domain1] = result1,
                        [domain2] = result2,
                    },
                },
            },
        };
    }

    [Fact]
    public void Serialize_RoundTrips_Successfully()
    {
        var results = new RefreshResults
        {
            Version = new DateTimeOffset(2026, 7, 12, 2, 0, 0, TimeSpan.Zero),
            Results = MakeResults("whois.nic.uk", "uk", "found", "google.co.uk", new DomainResult
            {
                Timestamp = new DateTimeOffset(2026, 7, 12, 2, 1, 15, TimeSpan.Zero),
                MatchedTemplate = "whois.nic.uk/uk/found/01",
                ExtractedFields = ["DomainName", "Registrar", "CreatedDate"],
                Error = null,
            }),
        };

        var json = RefreshResults.Serialize(results);
        var deserialized = RefreshResults.Deserialize(json);

        Assert.Equal(results.Version, deserialized.Version);
        var domainResult = deserialized.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.Equal("whois.nic.uk/uk/found/01", domainResult.MatchedTemplate);
        Assert.Equal(3, domainResult.ExtractedFields.Count);
        Assert.Null(domainResult.Error);
    }

    [Fact]
    public void Serialize_WithError_RoundTrips()
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = MakeResults("whois.denic.de", "de", "found", "google.de", new DomainResult
            {
                Timestamp = DateTimeOffset.UtcNow,
                MatchedTemplate = null,
                ExtractedFields = [],
                Error = new QueryError
                {
                    Type = QueryErrorType.ConnectionRefused,
                    Message = "Connection refused",
                    Detail = "whois.denic.de:43",
                },
            }),
        };

        var json = RefreshResults.Serialize(results);
        var deserialized = RefreshResults.Deserialize(json);

        var error = deserialized.Results["whois.denic.de"]["de"]["found"]["google.de"].Error;
        Assert.NotNull(error);
        Assert.Equal(QueryErrorType.ConnectionRefused, error.Type);
        Assert.Equal("Connection refused", error.Message);
    }

    [Fact]
    public void Prune_RemovesDomains_NotInRegistry()
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = MakeResultsTwoDomains(
                "whois.nic.uk", "uk", "found",
                "google.co.uk", new DomainResult
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    MatchedTemplate = "whois.nic.uk/uk/found/01",
                    ExtractedFields = ["DomainName"],
                    Error = null,
                },
                "removed-domain.co.uk", new DomainResult
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    MatchedTemplate = "whois.nic.uk/uk/found/01",
                    ExtractedFields = ["DomainName"],
                    Error = null,
                }),
        };

        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                ["found"] = ["google.co.uk"],
            }),
        });

        results.Prune(registry);

        Assert.Single(results.Results["whois.nic.uk"]["uk"]["found"]);
        Assert.True(results.Results["whois.nic.uk"]["uk"]["found"].ContainsKey("google.co.uk"));
    }
}
