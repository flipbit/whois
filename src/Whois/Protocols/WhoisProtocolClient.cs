using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;

namespace Whois.Protocols;

internal sealed class WhoisProtocolClient : IProtocolClient
{
    private const string JapanTldSuffix = ".jp";
    private const string JapanEnglishQuerySuffix = "/e";

    private readonly ITcpReader _tcpReader;
    private readonly IBootstrapRegistry _bootstrap;
    private readonly WhoisParser _parser;
    private readonly WhoisOptions _options;
    private readonly ILogger<WhoisProtocolClient> _logger;

    public WhoisProtocolClient(
        ITcpReader tcpReader,
        IBootstrapRegistry bootstrap,
        WhoisParser parser,
        WhoisOptions options)
        : this(tcpReader, bootstrap, parser, options, NullLogger<WhoisProtocolClient>.Instance)
    {
    }

    public WhoisProtocolClient(
        ITcpReader tcpReader,
        IBootstrapRegistry bootstrap,
        WhoisParser parser,
        WhoisOptions options,
        ILogger<WhoisProtocolClient> logger)
    {
        _tcpReader = tcpReader;
        _bootstrap = bootstrap;
        _parser = parser;
        _options = options;
        _logger = logger;
    }

    public LookupProtocol Protocol => LookupProtocol.Whois;

    public async Task<ProtocolResponse> Query(WhoisRequest request, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var encoding = request.Encoding ?? _options.Encoding;
        var timeout = request.TimeoutSeconds ?? _options.TimeoutSeconds;
        var followReferrer = request.FollowReferrer ?? _options.FollowReferrer;

        // Determine starting server
        string? whoisServer;
        if (request.WhoisServer != null)
        {
            whoisServer = request.WhoisServer.Value;
        }
        else
        {
            var tld = HostName.TryParse(request.Query, out var hostName) ? hostName!.Tld : request.Query;
            whoisServer = await _bootstrap.GetWhoisServer(tld, ct).ConfigureAwait(false);
            if (whoisServer == null)
            {
                throw new WhoisException($"No WHOIS server found for TLD: {tld}");
            }
        }

        var referralChain = new List<string>();
        var visitedServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        WhoisRecord? bestRecord = null;
        string? bestServer = null;
        string? bestContent = null;

        while (whoisServer != null)
        {
            ct.ThrowIfCancellationRequested();

            // Loop detection
            if (!visitedServers.Add(whoisServer))
                break;
            referralChain.Add(whoisServer);

            // Depth limit
            if (visitedServers.Count > _options.MaxWhoisReferralDepth)
            {
                _logger.LogWarning("WHOIS: referral depth limit ({MaxDepth}) reached for {Query}", _options.MaxWhoisReferralDepth, request.Query);
                break;
            }

            // Build query (Japanese domains return English results with /e suffix)
            var query = request.Query;
            if (query.EndsWith(JapanTldSuffix, StringComparison.Ordinal)) query += JapanEnglishQuerySuffix;

            // Download
            var content = await _tcpReader.Read(
                whoisServer, 43, query, encoding, timeout, ct).ConfigureAwait(false);

            _logger.LogDebug("WHOIS: downloaded {ByteCount} bytes from {Server}", content.Length, whoisServer);

            // Parse
            var record = _parser.Parse(whoisServer, content);

            // Keep the response with the most parsed fields
            if (bestRecord == null || record.FieldsParsed > bestRecord.FieldsParsed)
            {
                bestRecord = record;
                bestServer = whoisServer;
                bestContent = content;
            }
            else if (record.FieldsParsed == 0 && bestRecord.FieldsParsed > 0)
            {
                break;
            }

            if (!followReferrer) break;

            // Follow referral to next server
            whoisServer = record.WhoisServer?.Value;
            if (whoisServer != null)
            {
                _logger.LogDebug("WHOIS: following referral to {Server}", whoisServer);
            }
        }

        if (bestRecord == null)
        {
            throw new WhoisException($"No WHOIS response received for {request.Query}");
        }

        sw.Stop();

        return new ProtocolResponse
        {
            RawContent = bestContent!,
            Protocol = LookupProtocol.Whois,
            Response = WhoisRecordMapper.ToDomainInfo(bestRecord),
            Diagnostics = WhoisRecordMapper.ToDiagnostics(
                bestRecord, bestServer!, sw.Elapsed, referralChain.AsReadOnly()),
        };
    }
}
