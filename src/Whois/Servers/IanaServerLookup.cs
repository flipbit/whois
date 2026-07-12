using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Tokens;
using Whois.Net;
using Whois.Parsers;

namespace Whois.Servers;

/// <summary>
/// Class to lookup a WHOIS server for a TLD from IANA
/// </summary>
public class IanaServerLookup : IWhoisServerLookup
{
    private const string IanaUrl = "whois.iana.org";

    private readonly ILogger<IanaServerLookup> _logger;
    private readonly Lazy<TemplateMatcher> _ianaTemplate;
    private readonly ResourceReader _resourceReader;

    /// <summary>
    /// The <see cref="ITcpReader"/> to use for network requests
    /// </summary>
    public ITcpReader TcpReader { get; set; }

    /// <summary>
    /// Creates a new instance of the IANA Server Lookup
    /// </summary>
    public IanaServerLookup() : this(new TcpReader(), NullLogger<IanaServerLookup>.Instance)
    {
    }

    public IanaServerLookup(ITcpReader tcpReader) : this(tcpReader, NullLogger<IanaServerLookup>.Instance)
    {
    }

    public IanaServerLookup(ITcpReader tcpReader, ILogger<IanaServerLookup> logger)
    {
        _ianaTemplate = new Lazy<TemplateMatcher>(CreateIanaTemplate);
        _resourceReader = new ResourceReader();
        TcpReader = tcpReader;
        _logger = logger;
    }

    public async Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
    {
        var tld = GetTld(request.Query);

        var content = await Download(tld, request, cancellationToken).ConfigureAwait(false);

        // Reflect the raw response onto a ParsedWhoisServer object
        var matcher = _ianaTemplate.Value;
        var result = matcher.Tokenize(content);

        if (result.Success)
        {
            var match = result.BestMatch!.Assign<WhoisResponse>();

            match.Content = content;

            return match;
        }

        return new WhoisResponse
        {
            Content = content,
            DomainName = new HostName(tld),
            Status = WhoisStatus.Unknown,
        };
    }

    private async Task<string> Download(string tld, WhoisRequest request, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Looking up Root TLD server for {Tld} from {IanaUrl}", tld, IanaUrl);

        var response = await TcpReader.Read(IanaUrl, 43, tld.ToUpperInvariant(), request.Encoding, request.TimeoutSeconds, cancellationToken).ConfigureAwait(false);

        _logger.LogDebug("Received {ByteCount:###,###,##0} byte(s).", response.Length);

        return response;
    }

    private TemplateMatcher CreateIanaTemplate()
    {
        var options = new TokenizerOptions()
            .WithTransformer<CleanDomainStatusTransformer>()
            .WithTransformer<ToHostNameTransformer>();

        var matcher = new TemplateMatcher(options);

        var resourceNames = _resourceReader.GetNames("whois.iana.org");

        foreach (var resourceName in resourceNames)
        {
            var content = _resourceReader.GetContent(resourceName);

            matcher.RegisterTemplate(content);
        }

        return matcher;
    }

    private string GetTld(string domain)
    {
        var tld = domain;

        if (!string.IsNullOrEmpty(domain))
        {
            var parts = domain.Split('.');

            if (parts.Length > 1) tld = parts[parts.Length - 1];
        }

        return tld;
    }
}
