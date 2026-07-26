using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Whois.Net;
using Whois.Servers;

namespace Whois.Protocols;

internal sealed class RdapProtocolClient : IProtocolClient
{
    private const int MaxResponseSizeBytes = 2 * 1024 * 1024; // 2 MB

    private readonly HttpClient _httpClient;
    private readonly IBootstrapRegistry _bootstrap;
    private readonly WhoisOptions _options;
    private readonly ILogger<RdapProtocolClient> _logger;

    public RdapProtocolClient(
        HttpClient httpClient,
        IBootstrapRegistry bootstrap,
        WhoisOptions options)
        : this(httpClient, bootstrap, options, NullLogger<RdapProtocolClient>.Instance)
    {
    }

    public RdapProtocolClient(
        HttpClient httpClient,
        IBootstrapRegistry bootstrap,
        WhoisOptions options,
        ILogger<RdapProtocolClient> logger)
    {
        _httpClient = httpClient;
        _bootstrap = bootstrap;
        _options = options;
        _logger = logger;
    }

    public LookupProtocol Protocol => LookupProtocol.Rdap;

    public async Task<ProtocolResponse> Query(WhoisRequest request, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();

        ValidateQuery(request.Query);

        var tld = HostName.TryParse(request.Query, out var hostName) ? hostName!.Tld : request.Query;
        var baseUrl = await _bootstrap.GetRdapBaseUrl(tld, ct).ConfigureAwait(false);
        if (baseUrl == null)
        {
            throw new WhoisException($"No RDAP endpoint available for TLD: {tld}");
        }

        var encodedQuery = Uri.EscapeDataString(request.Query);
        var url = $"{baseUrl.TrimEnd('/')}/domain/{encodedQuery}";
        ValidateUrl(url);

        _logger.LogDebug("RDAP: querying {Url}", url);

        var timeout = request.TimeoutSeconds ?? _options.TimeoutSeconds;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeout));

        HttpResponseMessage httpResponse;
        try
        {
            httpResponse = await _httpClient.GetAsync(url, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new WhoisException(FormattableString.Invariant($"RDAP request timed out after {timeout} seconds: {url}"));
        }
        catch (HttpRequestException ex)
        {
            throw new WhoisException($"RDAP request failed for {url}: {ex.Message}", ex);
        }

        var statusCode = (int)httpResponse.StatusCode;
        _logger.LogDebug("RDAP: received HTTP {StatusCode} from {Url}", statusCode, url);

        if (httpResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            sw.Stop();
            return new ProtocolResponse
            {
                RawContent = string.Empty,
                Protocol = LookupProtocol.Rdap,
                Response = new DomainInfo
                {
                    DomainName = hostName,
                    Status = RegistrationStatus.NotFound,
                },
                Diagnostics = new LookupDiagnostics
                {
                    ServerUrl = url,
                    HttpStatusCode = statusCode,
                    Duration = sw.Elapsed,
                },
            };
        }

        if (statusCode == 429)
        {
            sw.Stop();
            return new ProtocolResponse
            {
                RawContent = string.Empty,
                Protocol = LookupProtocol.Rdap,
                Response = new DomainInfo
                {
                    DomainName = hostName,
                    Status = RegistrationStatus.Throttled,
                },
                Diagnostics = new LookupDiagnostics
                {
                    ServerUrl = url,
                    HttpStatusCode = statusCode,
                    Duration = sw.Elapsed,
                },
            };
        }

        if (!httpResponse.IsSuccessStatusCode)
        {
            throw new WhoisException(FormattableString.Invariant($"RDAP server returned HTTP {statusCode} for {url}"));
        }

        var json = await ReadWithSizeLimit(httpResponse, MaxResponseSizeBytes, ct).ConfigureAwait(false);

        var domainInfo = RdapParser.Parse(json);

        sw.Stop();

        return new ProtocolResponse
        {
            RawContent = json,
            Protocol = LookupProtocol.Rdap,
            Response = domainInfo,
            Diagnostics = new LookupDiagnostics
            {
                FieldsParsed = CountFields(domainInfo),
                ServerUrl = url,
                HttpStatusCode = statusCode,
                Duration = sw.Elapsed,
            },
        };
    }

    private static void ValidateQuery(string query)
    {
        if (query.IndexOfAny(['/', '?', '#', '@', ' ', '\t', '\n', '\r']) >= 0)
        {
            throw new WhoisException($"Invalid characters in RDAP query: {query}");
        }
    }

    private static void ValidateUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new WhoisException($"Invalid RDAP URL: {url}");
        }

        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            throw new WhoisException($"RDAP URL must use HTTPS: {url}");
        }
    }

    private static async Task<string> ReadWithSizeLimit(HttpResponseMessage response, int maxBytes, CancellationToken ct)
    {
        // Use the shim -- the outer CancellationTokenSource handles timeout via GetAsync.
        using var stream = await NetStandardShims.ReadAsStreamAsync(response.Content, ct).ConfigureAwait(false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var buffer = new char[8192];
        var sb = new StringBuilder();
        int charsRead;

        while ((charsRead = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            sb.Append(buffer, 0, charsRead);
            if (sb.Length > maxBytes)
            {
                throw new WhoisException(FormattableString.Invariant($"RDAP response exceeds maximum size of {maxBytes} bytes"));
            }
        }

        return sb.ToString();
    }

    private static int CountFields(DomainInfo info)
    {
        var count = 0;
        if (info.DomainName != null) count++;
        if (info.RegistryDomainId != null) count++;
        if (info.Registered.HasValue) count++;
        if (info.Updated.HasValue) count++;
        if (info.Expiration.HasValue) count++;
        if (info.Registrar != null) count++;
        if (info.Registrant != null) count++;
        if (info.TechnicalContact != null) count++;
        if (info.AdminContact != null) count++;
        count += info.NameServers.Count;
        count += info.DomainStatus.Count;
        return count;
    }
}
