using System.Text.Json;
using System.Text.Json.Serialization;

namespace WhoisRefresh.Domain;

public enum QueryErrorType
{
    Timeout,
    ConnectionRefused,
    RateLimited,
    AccessDenied,
    ParseFailure,
    ResponseTooLarge,
    Unknown
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
    public List<string> ExtractedFields { get; set; } = [];
    public QueryError? Error { get; set; }
}

public class RefreshResults
{
    public DateTimeOffset Version { get; set; }

    public Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, DomainResult>>>> Results { get; set; } = new();

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
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
            if (!registry.Servers.ContainsKey(serverName))
            {
                serversToRemove.Add(serverName);
                continue;
            }

            var registryServer = registry.Servers[serverName];

            foreach (var (tld, statuses) in tlds)
            {
                foreach (var (status, domains) in statuses)
                {
                    var registryDomains = registryServer.Domains.GetValueOrDefault(status) ?? [];
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
