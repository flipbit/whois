using System.Text.Json;
using System.Text.Json.Serialization;

namespace Whois.Refresh.Domain;

public enum QueryErrorType
{
    Timeout,
    ConnectionRefused,
    RateLimited,
    AccessDenied,
    ParseFailure,
    ResponseTooLarge,
    Unknown,
}

public class QueryError
{
    public QueryErrorType Type { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Detail { get; set; }
}

public class DomainResult
{
    public DateTimeOffset Timestamp { get; set; }
    public string? MatchedTemplate { get; set; }
    public IList<string> ExtractedFields { get; set; } = [];
    public QueryError? Error { get; set; }
    public string? ActualStatus { get; set; }
}

public class RefreshResults
{
    public DateTimeOffset Version { get; set; }

    public IDictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>> Results { get; set; } = new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal);

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase), },
    };

    public static string Serialize(RefreshResults results)
    {
        return JsonSerializer.Serialize(results, SerializerOptions);
    }

    public static RefreshResults Deserialize(string json)
    {
        return JsonSerializer.Deserialize<RefreshResults>(json, SerializerOptions)
            ?? throw new InvalidOperationException("Failed to deserialize refresh results");
    }

    /// <summary>
    /// Removes entries for domains not present in the registry.
    /// </summary>
    public void Prune(DomainRegistryData registry)
    {
        var serversToRemove = new List<string>();

        foreach (var (serverName, tlds) in Results)
        {
            if (!registry.Servers.TryGetValue(serverName, out var registryServer))
            {
                serversToRemove.Add(serverName);
                continue;
            }

            foreach (var (tld, statuses) in tlds)
            {
                foreach (var (status, domains) in statuses)
                {
                    registryServer.Domains.TryGetValue(status, out var registryDomains);
                    registryDomains ??= [];
                    var domainsToRemove = domains.Keys
                        .Where(d => !registryDomains.Contains(d))
                        .ToList();

                    foreach (var domain in domainsToRemove)
                    {
                        domains.Remove(domain);
                    }
                }
            }
        }

        foreach (var server in serversToRemove)
        {
            Results.Remove(server);
        }
    }
}
