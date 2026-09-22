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
    private readonly IIanaServerLookup _ianaLookup;
    private readonly WhoisParser _parser;
    private readonly WhoisOptions _options;
    private readonly ILogger<WhoisProtocolClient> _logger;

    public WhoisProtocolClient(
        ITcpReader tcpReader,
        IIanaServerLookup ianaLookup,
        WhoisParser parser,
        WhoisOptions options)
        : this(tcpReader, ianaLookup, parser, options, NullLogger<WhoisProtocolClient>.Instance)
    {
    }

    public WhoisProtocolClient(
        ITcpReader tcpReader,
        IIanaServerLookup ianaLookup,
        WhoisParser parser,
        WhoisOptions options,
        ILogger<WhoisProtocolClient> logger)
    {
        _tcpReader = tcpReader;
        _ianaLookup = ianaLookup;
        _parser = parser;
        _options = options;
        _logger = logger;
    }

    public LookupProtocol Protocol => LookupProtocol.Whois;

    public async Task<ProtocolResponse> Query(LookupRequest request, CancellationToken ct)
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
        else if (request is IpRequest ipReq)
        {
            whoisServer = await _ianaLookup.GetWhoisServer(ipReq.Address, ct).ConfigureAwait(false);
            if (whoisServer == null)
                throw new WhoisException($"No WHOIS server found for IP: {ipReq.Address.ToString()}");
        }
        else
        {
            var domainReq = (DomainRequest)request;
            var tld = HostName.TryParse(domainReq.Query, out var hostName) ? hostName!.Tld : domainReq.Query;
            whoisServer = await _ianaLookup.GetWhoisServer(tld, ct).ConfigureAwait(false);
            if (whoisServer == null)
                throw new WhoisException($"No WHOIS server found for TLD: {tld}");
        }

        if (request is IpRequest ipRequest)
        {
            return await QueryIp(ipRequest, whoisServer, encoding, timeout, sw, ct).ConfigureAwait(false);
        }

        return await QueryDomain((DomainRequest)request, whoisServer, encoding, timeout, followReferrer, sw, ct).ConfigureAwait(false);
    }

    private async Task<ProtocolResponse> QueryDomain(DomainRequest request, string? whoisServer, System.Text.Encoding encoding, int timeout, bool followReferrer, Stopwatch sw, CancellationToken ct)
    {
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
            var port = request.Port ?? 43;
            var content = await _tcpReader.Read(
                whoisServer, port, query, encoding, timeout, ct).ConfigureAwait(false);

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
            Response = WhoisRecordMapper.Map(bestRecord),
            Diagnostics = WhoisRecordMapper.MapDiagnostics(
                bestRecord, bestServer!, sw.Elapsed, referralChain.AsReadOnly()),
        };
    }

    private async Task<ProtocolResponse> QueryIp(IpRequest request, string? whoisServer, System.Text.Encoding encoding, int timeout, Stopwatch sw, CancellationToken ct)
    {
        var referralChain = new List<string>();
        var visitedServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IpRecord? bestRecord = null;
        string? bestServer = null;
        string? bestContent = null;
        var queryString = request.Address.ToString();

        if (whoisServer != null)
        {
            ct.ThrowIfCancellationRequested();

            visitedServers.Add(whoisServer);
            referralChain.Add(whoisServer);

            // Download
            var port = request.Port ?? 43;
            var content = await _tcpReader.Read(
                whoisServer, port, queryString, encoding, timeout, ct).ConfigureAwait(false);

            _logger.LogDebug("WHOIS: downloaded {ByteCount} bytes from {Server}", content.Length, whoisServer);

            // Parse
            var record = _parser.Parse<IpRecord>(whoisServer, content);

            bestRecord = record;
            bestServer = whoisServer;
            bestContent = content;
        }

        if (bestRecord == null)
        {
            throw new WhoisException($"No WHOIS response received for {queryString}");
        }

        sw.Stop();

        return new ProtocolResponse
        {
            RawContent = bestContent!,
            Protocol = LookupProtocol.Whois,
            Response = WhoisRecordMapper.Map(bestRecord),
            Diagnostics = WhoisRecordMapper.MapDiagnostics(
                bestRecord, bestServer!, sw.Elapsed, referralChain.AsReadOnly()),
        };
    }
}
