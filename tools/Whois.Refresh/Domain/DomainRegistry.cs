using System.Text.Json;

namespace Whois.Refresh.Domain;

public record DomainRegistryData(IDictionary<string, ServerEntry> Servers)
{
    /// <summary>
    /// Groups servers by rate group. Servers without a rateGroup are each their own group
    /// (keyed by server name).
    /// </summary>
    public ILookup<string, KeyValuePair<string, ServerEntry>> GetRateGroups()
    {
        return Servers
            .Where(s => !s.Value.IsStatic)
            .ToLookup(s => s.Value.RateGroup ?? s.Key, StringComparer.Ordinal);
    }
}

public class DomainRegistryValidationException : Exception
{
    public DomainRegistryValidationException(string message) : base(message) { }
}

public static class DomainRegistry
{
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static readonly IReadOnlySet<string> ValidStatusKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "found", "not-found", "throttled", "reserved", "suspended", "inactive", "expired",
        "blocked", "deactivated", "error", "failed", "invalid", "locked", "not-assigned",
        "not-available", "out-of-service", "pending-delete", "quarantined", "redemption",
        "to-be-released", "unavailable", "unconfirmed",
    };

    public static async Task<DomainRegistryData> LoadAsync(string jsonc)
    {
        await Task.CompletedTask.ConfigureAwait(false); // Sync parse, async signature for file-based overload later

        using var doc = JsonDocument.Parse(jsonc, JsonOptions);
        var root = doc.RootElement;
        var serversElement = root.GetProperty("servers");

        var servers = new Dictionary<string, ServerEntry>(StringComparer.Ordinal);

        foreach (var serverProp in serversElement.EnumerateObject())
        {
            var serverName = serverProp.Name;
            ValidatePathComponent(serverName, "server name");

            var serverObj = serverProp.Value;

            var tld = serverObj.GetProperty("tld").GetString()!;
            ValidatePathComponent(tld, "tld");

            var isStatic = serverObj.TryGetProperty("static", out var staticProp) && staticProp.GetBoolean();
            var rateGroup = serverObj.TryGetProperty("rateGroup", out var rgProp) && rgProp.ValueKind != JsonValueKind.Null
                ? rgProp.GetString()
                : null;

            var domains = new Dictionary<string, IList<string>>(StringComparer.Ordinal);
            var domainsObj = serverObj.GetProperty("domains");

            // Track all domains across all statuses for this server to detect duplicates
            var allDomainsForServer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var statusProp in domainsObj.EnumerateObject())
            {
                var status = statusProp.Name;

                if (!ValidStatusKeys.Contains(status))
                {
                    throw new DomainRegistryValidationException(
                        $"Unknown status key '{status}' in server '{serverName}': valid keys are {string.Join(", ", ValidStatusKeys)}");
                }

                List<string> domainList = new List<string>();

                foreach (var domainElement in statusProp.Value.EnumerateArray())
                {
                    var domain = domainElement.GetString()!;
                    ValidateDomainName(domain);

                    if (allDomainsForServer.TryGetValue(domain, out var existingStatus))
                    {
                        throw new DomainRegistryValidationException(
                            $"Duplicate domain '{domain}' in server '{serverName}': listed under both '{existingStatus}' and '{status}'");
                    }

                    allDomainsForServer[domain] = status;
                    domainList.Add(domain);
                }

                domains[status] = domainList;
            }

            servers[serverName] = new ServerEntry(tld, isStatic, rateGroup, domains);
        }

        return new DomainRegistryData(servers);
    }

    public static async Task<DomainRegistryData> LoadFromFileAsync(string path)
    {
        var content = await File.ReadAllTextAsync(path).ConfigureAwait(false);
        return await LoadAsync(content).ConfigureAwait(false);
    }

    private static void ValidateDomainName(string domain)
    {
        if (domain.Contains('/', StringComparison.Ordinal) || domain.Contains('\\', StringComparison.Ordinal) || domain.Contains("..", StringComparison.Ordinal))
        {
            throw new DomainRegistryValidationException(
                $"Invalid domain name '{domain}': contains path separator or traversal sequence");
        }
    }

    private static void ValidatePathComponent(string value, string fieldName)
    {
        if (value.Contains('/', StringComparison.Ordinal) || value.Contains('\\', StringComparison.Ordinal) || value.Contains("..", StringComparison.Ordinal))
        {
            throw new DomainRegistryValidationException(
                $"Invalid {fieldName} '{value}': contains path separator or traversal sequence");
        }
    }
}
