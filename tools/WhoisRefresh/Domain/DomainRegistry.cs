using System.Text.Json;

namespace WhoisRefresh.Domain;

public record DomainRegistryData(Dictionary<string, ServerEntry> Servers)
{
    /// <summary>
    /// Groups servers by rate group. Servers without a rateGroup are each their own group
    /// (keyed by server name).
    /// </summary>
    public ILookup<string, KeyValuePair<string, ServerEntry>> GetRateGroups()
    {
        return Servers
            .Where(s => !s.Value.IsStatic)
            .ToLookup(s => s.Value.RateGroup ?? s.Key);
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
        AllowTrailingCommas = true
    };

    public static async Task<DomainRegistryData> LoadAsync(string jsonc)
    {
        await Task.CompletedTask; // Sync parse, async signature for file-based overload later

        using var doc = JsonDocument.Parse(jsonc, JsonOptions);
        var root = doc.RootElement;
        var serversElement = root.GetProperty("servers");

        var servers = new Dictionary<string, ServerEntry>();

        foreach (var serverProp in serversElement.EnumerateObject())
        {
            var serverName = serverProp.Name;
            var serverObj = serverProp.Value;

            var tld = serverObj.GetProperty("tld").GetString()!;
            var isStatic = serverObj.TryGetProperty("static", out var staticProp) && staticProp.GetBoolean();
            var rateGroup = serverObj.TryGetProperty("rateGroup", out var rgProp) && rgProp.ValueKind != JsonValueKind.Null
                ? rgProp.GetString()
                : null;

            var domains = new Dictionary<string, List<string>>();
            var domainsObj = serverObj.GetProperty("domains");

            foreach (var statusProp in domainsObj.EnumerateObject())
            {
                var status = statusProp.Name;
                var domainList = new List<string>();

                foreach (var domainElement in statusProp.Value.EnumerateArray())
                {
                    var domain = domainElement.GetString()!;
                    ValidateDomainName(domain);
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
        var content = await File.ReadAllTextAsync(path);
        return await LoadAsync(content);
    }

    private static void ValidateDomainName(string domain)
    {
        if (domain.Contains('/') || domain.Contains('\\') || domain.Contains(".."))
        {
            throw new DomainRegistryValidationException(
                $"Invalid domain name '{domain}': contains path separator or traversal sequence");
        }
    }
}
