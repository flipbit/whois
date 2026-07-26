using System.Text;
using Microsoft.Extensions.Logging;
using Whois.Templates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;

namespace Whois;

/// <summary>
/// Looks up WHOIS information
/// </summary>
public class WhoisLookup : IWhoisLookup
{
    private readonly ILogger<WhoisLookup> _logger;
    private readonly ITemplatePackProvider _packProvider;
    private int _autoUpdateTriggered = 0;

    // Static shared instances for non-DI use  -  created lazily.
    // The pack provider uses a static HttpClient and NullLoggers.
    private static readonly Lazy<TemplatePackProvider> SharedPackProvider = new(() =>
    {
        var options = new WhoisOptions();
        var cacheDir = GetDefaultCacheDirectory();
        var cacheLogger = NullLogger<CacheDirectoryManager>.Instance;
        var stateLogger = NullLogger<TemplateUpdateState>.Instance;
        var cache = new CacheDirectoryManager(cacheDir, cacheLogger);
        var state = new TemplateUpdateState(cache, stateLogger);
        return new TemplatePackProvider(options, NullLogger<TemplatePackProvider>.Instance, cache, state);
    });

    private static readonly Lazy<WhoisParser> SharedParser = new(() =>
        new WhoisParser(server => SharedPackProvider.Value.GetCachedTemplatePath(server)));

    /// <summary>
    /// The default <see cref="WhoisOptions"/> to use for this instance
    /// </summary>
    public WhoisOptions Options { get; set; }

    /// <summary>
    /// The WHOIS parser that parses the free text WHOIS responses into
    /// structured C# objects
    /// </summary>
    public WhoisParser Parser { get; private set; }

    /// <summary>
    /// The WHOIS Server Lookup that finds root TLD servers for queries
    /// </summary>
    public IWhoisServerLookup ServerLookup { get; set; }

    /// <summary>
    /// The TCP reader that performs the network requests
    /// </summary>
    public ITcpReader TcpReader { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the default options.
    /// Uses shared static instances of the parser and pack provider.
    /// </summary>
    public WhoisLookup() : this(new WhoisOptions())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the given <see cref="WhoisOptions"/>.
    /// Uses shared static instances of the parser and pack provider.
    /// </summary>
    public WhoisLookup(WhoisOptions options) : this(options, NullLogger<WhoisLookup>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="WhoisLookup"/> class for use with the Options pattern.
    /// Uses shared static instances of the parser and pack provider.
    /// </summary>
    public WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger)
        : this(options.Value, logger)
    {
    }

    /// <summary>
    /// Full DI constructor  -  all dependencies supplied by the container.
    /// </summary>
    public WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger, ITcpReader tcpReader, IWhoisServerLookup serverLookup, ITemplatePackProvider packProvider, WhoisParser parser)
    {
        Options = options.Value;
        _logger = logger;
        TcpReader = tcpReader;
        ServerLookup = serverLookup;
        _packProvider = packProvider;
        Parser = parser;
    }

    /// <summary>
    /// Internal constructor for testing  -  accepts explicit pack provider and parser.
    /// </summary>
    internal WhoisLookup(ITemplatePackProvider packProvider, WhoisParser parser)
        : this(new WhoisOptions(), NullLogger<WhoisLookup>.Instance, packProvider, parser)
    {
    }

    private WhoisLookup(WhoisOptions options, ILogger<WhoisLookup> logger)
        : this(options, logger, SharedPackProvider.Value, SharedParser.Value)
    {
    }

    private WhoisLookup(WhoisOptions options, ILogger<WhoisLookup> logger, ITemplatePackProvider packProvider, WhoisParser parser)
    {
        Options = options;
        _logger = logger;
        _packProvider = packProvider;
        Parser = parser;
        TcpReader = new TcpReader();
        ServerLookup = new IanaServerLookup(TcpReader);
    }

    /// <summary>
    /// Performs a WHOIS lookup on the specified domain.
    /// </summary>
    public Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default)
    {
        return Lookup(domain, Options.Encoding, cancellationToken);
    }

    /// <summary>
    /// Performs a WHOIS lookup on the specified domain with the given encoding.
    /// </summary>
    public Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default)
    {
        return Lookup(new WhoisRequest
        {
            Query = domain,
            Encoding = encoding,
            TimeoutSeconds = Options.TimeoutSeconds,
            FollowReferrer = Options.FollowReferrer,
        }, cancellationToken);
    }

    /// <summary>
    /// Performs a WHOIS lookup for the given request.
    /// </summary>
    public async Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(request.Query))
        {
            throw new ArgumentNullException(nameof(request), "Query must not be null or empty.");
        }

        // Trigger a background template update check on the first lookup when auto-update is enabled.
        if (Options.AutoUpdateTemplates && Interlocked.CompareExchange(ref _autoUpdateTriggered, 1, 0) == 0)
        {
#pragma warning disable CA1031 // Fire-and-forget: must catch all exceptions to prevent unobserved task faults
            _ = Task.Run(async () =>
            {
                try { await _packProvider.CheckForUpdate(CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { _logger.LogWarning(ex, "Background template update check failed"); }
            }, CancellationToken.None);
#pragma warning restore CA1031
        }

        // Trim leading '.'
        if (request.Query.Length > 0 && request.Query[0] == '.') request.Query = request.Query.Substring(1);

        // Validate domain name
        if (!HostName.TryParse(request.Query, out var hostName))
        {
            throw new WhoisException($"WHOIS Query Format Error: {request.Query}");
        }

        _logger.LogDebug("Looking up WHOIS response for: {HostName}", hostName!.Value);

        // Set our starting point
        WhoisResponse response;
        if (string.IsNullOrEmpty(request.WhoisServer))
        {
            // Lookup root WHOIS server for the TLD
            response = await ServerLookup.Lookup(request, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            // Use the given WHOIS server
            response = WhoisResponse.WithServerUrl(request.WhoisServer!);
        }

        // If query is for a top level domain, we're finished
        if (hostName!.IsTld) return response;

        // Main loop: download & parse WHOIS data and follow the referrer chain
        var whoisServer = response.WhoisServer;
        while (whoisServer != null)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Download
            var content = await Download(whoisServer.Value, request, cancellationToken).ConfigureAwait(false);

            // Parse result
            var parsed = Parser.Parse(whoisServer.Value, content);

            // Sanity check: ensure the last response has some data
            if (parsed.FieldsParsed == 0 && response.FieldsParsed > 0)
            {
                break;
            }

            // Build referrer chain
            response = response.Chain(parsed);

            // Check for referral loop
            if (!request.FollowReferrer) break;
            if (response.SeenServer(response.WhoisServer)) break;

            // Lookup result in referral server
            whoisServer = response.WhoisServer;
        }

        return response;
    }

    /// <inheritdoc />
    public TemplateStatus TemplateStatus => _packProvider.Status;

    /// <inheritdoc />
    public Task<TemplateUpdateResult> UpdateTemplates(CancellationToken cancellationToken = default) =>
        _packProvider.CheckForUpdate(cancellationToken);

    private async Task<string> Download(string url, WhoisRequest request, CancellationToken cancellationToken)
    {
        var query = request.Query;
        if (query.EndsWith("jp", StringComparison.Ordinal)) query += "/e";    // Return English .jp results

        var content = await TcpReader.Read(url, 43, query, request.Encoding, request.TimeoutSeconds, cancellationToken).ConfigureAwait(false);

        _logger.LogDebug("Lookup {Query}: Downloaded {ByteCount:###,###,##0} byte(s) from {Url}.", request.Query, content.Length, url);

        return content;
    }

    private static string GetDefaultCacheDirectory() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Whois",
            "templates");
}
