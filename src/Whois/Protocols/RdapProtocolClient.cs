using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Whois.Net;
using Whois.Servers;

namespace Whois.Protocols;

internal sealed class RdapProtocolClient : IProtocolClient
{
    private const int MaxResponseSizeChars = 2 * 1024 * 1024; // 2 MB

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

        var json = await ReadWithSizeLimit(httpResponse, MaxResponseSizeChars, ct).ConfigureAwait(false);

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

        // Reject non-default ports -- RDAP must use the standard HTTPS port 443.
        if (uri.Port != 443 && uri.Port != -1)
        {
            throw new WhoisException($"RDAP URL must use the default HTTPS port (443): {url}");
        }

        // Reject IP literal hosts that resolve to private/loopback/link-local addresses (SSRF prevention).
        // Hostname-based hosts are not validated here -- DNS resolution happens at request time.
        if (System.Net.IPAddress.TryParse(uri.Host, out var ip))
        {
            if (IsPrivateOrReservedAddress(ip))
            {
                throw new WhoisException($"RDAP URL targets a private or reserved IP address: {url}");
            }
        }
    }

    private static bool IsPrivateOrReservedAddress(System.Net.IPAddress ip)
    {
        // Normalize IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) to IPv4.
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // IPv4: check loopback (127.0.0.0/8), link-local (169.254.0.0/16),
            // and RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 127
                || (bytes[0] == 169 && bytes[1] == 254)
                || bytes[0] == 10
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168);
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // IPv6: check loopback (::1) and link-local (fe80::/10).
            if (ip.Equals(System.Net.IPAddress.IPv6Loopback)) return true;
            var bytes = ip.GetAddressBytes();
            // fe80::/10 -- first 10 bits are 1111111010
            return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
        }

        return false;
    }

    private static async Task<string> ReadWithSizeLimit(HttpResponseMessage response, int maxChars, CancellationToken ct)
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
            if (sb.Length > maxChars)
            {
                throw new WhoisException(FormattableString.Invariant($"RDAP response exceeds maximum size of {maxChars} characters"));
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
