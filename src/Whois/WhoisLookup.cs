using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Parsers;
using Whois.Protocols;
using Whois.Servers;

namespace Whois;

/// <summary>
/// Looks up WHOIS information using RDAP or WHOIS protocol based on bootstrap
/// data and caller preference.
/// </summary>
public class WhoisLookup : IWhoisLookup
{
    private readonly ILogger<WhoisLookup> _logger;
    private readonly IRdapRegistryCache _rdapRegistry;
    private readonly IIanaServerLookup _ianaLookup;
    private readonly IProtocolClient _whoisClient;
    private readonly IProtocolClient _rdapClient;
    private readonly WhoisOptions _options;

    private static readonly Lazy<WhoisParser> SharedParser = new(() => new WhoisParser());

    /// <summary>
    /// Initializes a new instance with default options (non-DI).
    /// </summary>
    public WhoisLookup() : this(new WhoisOptions())
    {
    }

    /// <summary>
    /// Initializes a new instance with the given options (non-DI).
    /// Each instance creates its own cache infrastructure that respects
    /// the provided options (timeouts, cache durations, etc.).
    /// </summary>
    public WhoisLookup(WhoisOptions options)
    {
        _options = options;
        _logger = NullLogger<WhoisLookup>.Instance;

        var httpClient = NetStandardShims.CreatePooledHttpClient();
        _rdapRegistry = new RdapRegistryCache(httpClient, options);
        _ianaLookup = new IanaServerLookup(new TcpReader(), options);

        var parser = SharedParser.Value;
        var tcpReader = new TcpReader();
        _whoisClient = new WhoisProtocolClient(tcpReader, _ianaLookup, parser, options);
        _rdapClient = new RdapProtocolClient(httpClient, _rdapRegistry, options);
    }

    /// <summary>
    /// DI constructor via Options pattern.
    /// </summary>
    internal WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger,
        IRdapRegistryCache rdapRegistry, IIanaServerLookup ianaLookup,
        IEnumerable<IProtocolClient> clients)
    {
        _options = options.Value;
        _logger = logger;
        _rdapRegistry = rdapRegistry;
        _ianaLookup = ianaLookup;

        var clientList = clients.ToList();
        _whoisClient = clientList.First(c => c.Protocol == LookupProtocol.Whois);
        _rdapClient = clientList.First(c => c.Protocol == LookupProtocol.Rdap);
    }

    /// <summary>
    /// Test constructor -- explicit dependencies for protocol client testing.
    /// </summary>
    internal WhoisLookup(WhoisOptions options, IRdapRegistryCache rdapRegistry,
        IIanaServerLookup ianaLookup, IList<IProtocolClient> clients)
    {
        _options = options;
        _logger = NullLogger<WhoisLookup>.Instance;
        _rdapRegistry = rdapRegistry;
        _ianaLookup = ianaLookup;

        _whoisClient = clients.First(c => c.Protocol == LookupProtocol.Whois);
        _rdapClient = clients.First(c => c.Protocol == LookupProtocol.Rdap);
    }

    /// <summary>
    /// The default <see cref="WhoisOptions"/> for this instance.
    /// </summary>
    public WhoisOptions Options => _options;

    public Task<LookupResult<DomainInfo>> Lookup(string domain, CancellationToken ct = default)
    {
        return Lookup(new WhoisRequest(domain), ct);
    }

    public async Task<LookupResult<DomainInfo>> Lookup(WhoisRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(request.Query))
        {
            throw new ArgumentNullException(nameof(request), "Query must not be null or empty.");
        }

        // Validate domain name
        var query = request.Query;
        if (query.Length > 0 && query[0] == '.') query = query.Substring(1);

        if (!HostName.TryParse(query, out var hostName))
        {
            throw new WhoisException($"WHOIS Query Format Error: {query}");
        }

        // Determine protocol
        var preference = request.PreferredProtocol ?? _options.PreferredProtocol;
        var tld = hostName!.Tld;
        var (client, rdapBaseUrl) = await SelectClient(preference, tld, ct).ConfigureAwait(false);

        _logger.LogDebug("Lookup {Query}: using {Protocol} protocol", query, client.Protocol);

        // Execute query
        var effectiveRequest = new WhoisRequest(query)
        {
            Encoding = request.Encoding,
            TimeoutSeconds = request.TimeoutSeconds,
            FollowReferrer = request.FollowReferrer,
            WhoisServer = request.WhoisServer,
            RdapBaseUrl = rdapBaseUrl,
        };

        ProtocolResponse response;
        try
        {
            response = await client.Query(effectiveRequest, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Lookup failed for {Query} using {Protocol}", query, client.Protocol);
            throw;
        }

        return new LookupResult<DomainInfo>(
            response.Response,
            response.Protocol,
            response.RawContent,
            response.Diagnostics);
    }

    private async Task<(IProtocolClient Client, string? RdapBaseUrl)> SelectClient(
        ProtocolPreference preference, string tld, CancellationToken ct)
    {
        switch (preference)
        {
            case ProtocolPreference.Whois:
                return (_whoisClient, null);

            case ProtocolPreference.Rdap:
                var rdapUrl = await _rdapRegistry.GetBaseUrl(tld, ct).ConfigureAwait(false);
                if (rdapUrl == null)
                    throw new WhoisException($"RDAP is not available for TLD: {tld}");
                return (_rdapClient, rdapUrl);

            case ProtocolPreference.Auto:
            default:
                var autoRdapUrl = await _rdapRegistry.GetBaseUrl(tld, ct).ConfigureAwait(false);
                if (autoRdapUrl != null)
                    return (_rdapClient, autoRdapUrl);
                _logger.LogInformation("RDAP not available for TLD {Tld}, falling back to WHOIS", tld);
                return (_whoisClient, null);
        }
    }

    public void ClearCache()
    {
        _rdapRegistry.ClearCache();
        _ianaLookup.ClearCache();
        _logger.LogInformation("All server discovery caches cleared");
    }

}
