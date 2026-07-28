using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Whois.Net;

namespace Whois.Servers;

/// <summary>
/// Discovers WHOIS servers by querying whois.iana.org over TCP port 43.
/// Results are cached per-TLD with a configurable TTL.
/// </summary>
public class IanaServerLookup : IIanaServerLookup
{
    private const string IanaHost = "whois.iana.org";
    private const int WhoisPort = 43;

    private readonly ITcpReader _tcpReader;
    private readonly WhoisOptions _options;
    private readonly ILogger<IanaServerLookup> _logger;
    private readonly ConcurrentDictionary<string, (string? Server, DateTime FetchedAt)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public IanaServerLookup(ITcpReader tcpReader, WhoisOptions options)
        : this(tcpReader, options, NullLogger<IanaServerLookup>.Instance)
    {
    }

    public IanaServerLookup(ITcpReader tcpReader, WhoisOptions options,
        ILogger<IanaServerLookup> logger)
    {
        _tcpReader = tcpReader;
        _options = options;
        _logger = logger;
    }

    public async Task<string?> GetWhoisServer(string tld, CancellationToken ct = default)
    {
        var normalizedTld = tld.ToLowerInvariant();

        if (_cache.TryGetValue(normalizedTld, out var entry) &&
            DateTime.UtcNow - entry.FetchedAt < _options.TldServerCacheDuration)
        {
            _logger.LogDebug("IANA lookup: cache hit for TLD {Tld}: {Server}", tld, entry.Server ?? "(none)");
            return entry.Server;
        }

        var response = await _tcpReader.Read(
            IanaHost, WhoisPort, normalizedTld, Encoding.UTF8, _options.TimeoutSeconds, ct).ConfigureAwait(false);

        var server = ParseWhoisServer(response);
        _cache[normalizedTld] = (server, DateTime.UtcNow);

        _logger.LogDebug("IANA lookup: fetched server for TLD {Tld}: {Server}", tld, server ?? "(none)");
        return server;
    }

    public void ClearCache()
    {
        _cache.Clear();
        _logger.LogInformation("IANA server lookup cache cleared");
    }

    /// <summary>
    /// Parses the 'whois:' field from an IANA WHOIS response.
    /// Returns null if the field is not present or empty.
    /// </summary>
    internal static string? ParseWhoisServer(string response)
    {
        using var reader = new StringReader(response);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var trimmed = line.TrimStart();
            if (!trimmed.StartsWith("whois:", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = trimmed.Substring("whois:".Length).Trim();
            return value.Length > 0 ? value : null;
        }

        return null;
    }
}
