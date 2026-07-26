using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Whois.Servers;

/// <summary>
/// Provides server discovery for both RDAP and WHOIS protocols using embedded IANA bootstrap data.
/// Loads from embedded JSON resources on first access (lazy, thread-safe). No network calls.
/// </summary>
public class BootstrapRegistry : IBootstrapRegistry
{
    private const string RdapResourceName = "Whois.Resources.bootstrap.rdap-dns.json";
    private const string WhoisResourceName = "Whois.Resources.bootstrap.whois-dns.json";

    private readonly ILogger<BootstrapRegistry> _logger;
    private volatile Lazy<(Dictionary<string, string> Rdap, Dictionary<string, string> Whois)> _data;

    public BootstrapRegistry() : this(NullLogger<BootstrapRegistry>.Instance)
    {
    }

    public BootstrapRegistry(ILogger<BootstrapRegistry> logger)
    {
        _logger = logger;
        _data = CreateLazy();
    }

    public Task<string?> GetRdapBaseUrl(string tld, CancellationToken ct)
    {
        var data = _data.Value;
        data.Rdap.TryGetValue(tld.ToLowerInvariant(), out var url);
        return Task.FromResult(url);
    }

    public Task<string?> GetWhoisServer(string tld, CancellationToken ct)
    {
        var data = _data.Value;
        data.Whois.TryGetValue(tld.ToLowerInvariant(), out var server);
        return Task.FromResult(server);
    }

    public Task Refresh(CancellationToken ct)
    {
        _data = CreateLazy();
        return Task.CompletedTask;
    }

    private Lazy<(Dictionary<string, string> Rdap, Dictionary<string, string> Whois)> CreateLazy()
    {
        return new Lazy<(Dictionary<string, string>, Dictionary<string, string>)>(() =>
        {
            var rdap = ParseBootstrapJson(ResourceReader.GetContent(RdapResourceName));
            var whois = ParseWhoisBootstrapJson(ResourceReader.GetContent(WhoisResourceName));

            _logger.LogDebug(
                "Bootstrap registry loaded: {RdapCount} RDAP endpoints, {WhoisCount} WHOIS servers",
                rdap.Count, whois.Count);

            return (rdap, whois);
        });
    }

    /// <summary>
    /// Parses an IANA RDAP bootstrap JSON file, returning a map of TLD to HTTPS base URL.
    /// Only HTTPS URLs are accepted; entries with no HTTPS URL are skipped.
    /// </summary>
    internal static Dictionary<string, string> ParseBootstrapJson(string json)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("services", out var services)) return result;

        foreach (var service in services.EnumerateArray())
        {
            var entries = service.EnumerateArray().ToArray();
            if (entries.Length < 2) continue;

            var tlds = entries[0];
            var urls = entries[1];

            // Pick the first HTTPS URL -- HTTP-only entries are skipped
            string? baseUrl = null;
            foreach (var url in urls.EnumerateArray())
            {
                var urlStr = url.GetString();
                if (urlStr != null && urlStr.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    baseUrl = urlStr;
                    break;
                }
            }

            if (baseUrl == null) continue;

            foreach (var tld in tlds.EnumerateArray())
            {
                var tldStr = tld.GetString();
                if (tldStr != null)
                {
                    result[tldStr.ToLowerInvariant()] = baseUrl;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Parses a WHOIS server bootstrap JSON file (same structure as IANA RDAP bootstrap),
    /// returning a map of TLD to WHOIS server hostname.
    /// </summary>
    internal static Dictionary<string, string> ParseWhoisBootstrapJson(string json)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("services", out var services)) return result;

        foreach (var service in services.EnumerateArray())
        {
            var entries = service.EnumerateArray().ToArray();
            if (entries.Length < 2) continue;

            var tlds = entries[0];
            var servers = entries[1];

            var server = servers.EnumerateArray().FirstOrDefault().GetString();
            if (server == null) continue;

            foreach (var tld in tlds.EnumerateArray())
            {
                var tldStr = tld.GetString();
                if (tldStr != null)
                {
                    result[tldStr.ToLowerInvariant()] = server;
                }
            }
        }

        return result;
    }
}
