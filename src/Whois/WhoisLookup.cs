using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Parsers;
using Whois.Protocols;
using Whois.Servers;
using Whois.Templates;

namespace Whois;

/// <summary>
/// Looks up WHOIS information using RDAP or WHOIS protocol based on bootstrap
/// data and caller preference.
/// </summary>
public class WhoisLookup : IWhoisLookup
{
    private readonly ILogger<WhoisLookup> _logger;
    private readonly IBootstrapRegistry _bootstrap;
    private readonly IProtocolClient _whoisClient;
    private readonly IProtocolClient _rdapClient;
    private readonly WhoisOptions _options;

    // Template management (WHOIS-specific, not on the interface)
    private readonly ITemplatePackProvider? _packProvider;
    private int _autoUpdateTriggered;

    // --- Static shared instances for non-DI use ---
    private static readonly Lazy<HttpClient> SharedHttpClient = new(NetStandardShims.CreatePooledHttpClient);

    private static readonly Lazy<BootstrapRegistry> SharedBootstrap = new(() =>
        new BootstrapRegistry(SharedHttpClient.Value, new WhoisOptions()));

    private static readonly Lazy<TemplatePackProvider> SharedPackProvider = new(() =>
    {
        var options = new WhoisOptions();
        var cacheDir = WhoisOptions.GetDefaultCacheDirectory();
        var cache = new CacheDirectoryManager(cacheDir, NullLogger<CacheDirectoryManager>.Instance);
        var state = new TemplateUpdateState(cache, NullLogger<TemplateUpdateState>.Instance);
        return new TemplatePackProvider(options, NullLogger<TemplatePackProvider>.Instance, cache, state);
    });

    private static readonly Lazy<WhoisParser> SharedParser = new(() =>
        new WhoisParser(server => SharedPackProvider.Value.GetCachedTemplatePath(server)));

    /// <summary>
    /// Initializes a new instance with default options (non-DI).
    /// </summary>
    public WhoisLookup() : this(new WhoisOptions())
    {
    }

    /// <summary>
    /// Initializes a new instance with the given options (non-DI).
    /// </summary>
    public WhoisLookup(WhoisOptions options)
    {
        _options = options;
        _logger = NullLogger<WhoisLookup>.Instance;
        _bootstrap = SharedBootstrap.Value;
        _packProvider = SharedPackProvider.Value;

        var parser = SharedParser.Value;
        var tcpReader = new TcpReader();
        _whoisClient = new WhoisProtocolClient(tcpReader, _bootstrap, parser, options);
        _rdapClient = new RdapProtocolClient(SharedHttpClient.Value, _bootstrap, options);
    }

    /// <summary>
    /// DI constructor via Options pattern.
    /// </summary>
    internal WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger,
        IBootstrapRegistry bootstrap, IEnumerable<IProtocolClient> clients,
        ITemplatePackProvider packProvider)
    {
        _options = options.Value;
        _logger = logger;
        _bootstrap = bootstrap;
        _packProvider = packProvider;

        var clientList = clients.ToList();
        _whoisClient = clientList.First(c => c.Protocol == LookupProtocol.Whois);
        _rdapClient = clientList.First(c => c.Protocol == LookupProtocol.Rdap);
    }

    /// <summary>
    /// Test constructor -- explicit dependencies for protocol client testing.
    /// </summary>
    internal WhoisLookup(WhoisOptions options, IBootstrapRegistry bootstrap, IList<IProtocolClient> clients)
    {
        _options = options;
        _logger = NullLogger<WhoisLookup>.Instance;
        _bootstrap = bootstrap;

        _whoisClient = clients.First(c => c.Protocol == LookupProtocol.Whois);
        _rdapClient = clients.First(c => c.Protocol == LookupProtocol.Rdap);
    }

    /// <summary>
    /// Test constructor -- for template management tests that share a provider.
    /// </summary>
    internal WhoisLookup(ITemplatePackProvider packProvider, WhoisParser parser)
    {
        _options = new WhoisOptions();
        _logger = NullLogger<WhoisLookup>.Instance;
        _bootstrap = SharedBootstrap.Value;
        _packProvider = packProvider;

        var tcpReader = new TcpReader();
        _whoisClient = new WhoisProtocolClient(tcpReader, _bootstrap, parser, _options);
        _rdapClient = new RdapProtocolClient(SharedHttpClient.Value, _bootstrap, _options);
    }

    /// <summary>
    /// The default <see cref="WhoisOptions"/> for this instance.
    /// </summary>
    public WhoisOptions Options => _options;

    /// <summary>
    /// Current template cache status (WHOIS-specific, not on IWhoisLookup).
    /// </summary>
    public TemplateStatus? TemplateStatus => _packProvider?.Status;

    /// <summary>
    /// Manually trigger a template update check (WHOIS-specific, not on IWhoisLookup).
    /// </summary>
    public Task<TemplateUpdateResult>? UpdateTemplates(CancellationToken cancellationToken = default) =>
        _packProvider?.CheckForUpdate(cancellationToken);

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

        // Trigger background template update on first lookup
        if (_packProvider != null && _options.AutoUpdateTemplates &&
            Interlocked.CompareExchange(ref _autoUpdateTriggered, 1, 0) == 0)
        {
#pragma warning disable CA1031
            _ = Task.Run(async () =>
            {
                try { await _packProvider.CheckForUpdate(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { _logger.LogWarning(ex, "Background template update check failed"); }
            }, CancellationToken.None);
#pragma warning restore CA1031
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
        var client = await SelectClient(preference, tld, ct).ConfigureAwait(false);

        _logger.LogDebug("Lookup {Query}: using {Protocol} protocol", query, client.Protocol);

        // Execute query
        var effectiveRequest = new WhoisRequest(query)
        {
            Encoding = request.Encoding,
            TimeoutSeconds = request.TimeoutSeconds,
            FollowReferrer = request.FollowReferrer,
            WhoisServer = request.WhoisServer,
        };

        var response = await client.Query(effectiveRequest, ct).ConfigureAwait(false);

        return new LookupResult<DomainInfo>(
            response.Response,
            response.Protocol,
            response.RawContent,
            response.Diagnostics);
    }

    private async Task<IProtocolClient> SelectClient(ProtocolPreference preference, string tld, CancellationToken ct)
    {
        switch (preference)
        {
            case ProtocolPreference.Whois:
                return _whoisClient;

            case ProtocolPreference.Rdap:
                var rdapUrl = await _bootstrap.GetRdapBaseUrl(tld, ct).ConfigureAwait(false);
                if (rdapUrl == null)
                    throw new WhoisException($"RDAP is not available for TLD: {tld}");
                return _rdapClient;

            case ProtocolPreference.Auto:
            default:
                var autoRdapUrl = await _bootstrap.GetRdapBaseUrl(tld, ct).ConfigureAwait(false);
                if (autoRdapUrl != null)
                    return _rdapClient;
                return _whoisClient;
        }
    }

}
