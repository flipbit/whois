using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Whois.Servers;

/// <summary>
/// Provides server discovery for both RDAP and WHOIS protocols.
/// RDAP data is fetched from IANA at runtime and cached in memory.
/// WHOIS data is loaded from an embedded resource (no IANA JSON endpoint exists).
/// </summary>
public class BootstrapRegistry : IBootstrapRegistry
{
    private const string WhoisResourceName = "Whois.Resources.bootstrap.whois-dns.json";
    private const int MaxResponseSizeChars = 1 * 1024 * 1024; // 1 MB

    private readonly HttpClient _httpClient;
    private readonly WhoisOptions _options;
    private readonly ILogger<BootstrapRegistry> _logger;

#pragma warning disable CA2213 // SemaphoreSlim: singleton lifetime, no Dispose on IBootstrapRegistry by design
    private readonly SemaphoreSlim _rdapLock = new(1, 1);
#pragma warning restore CA2213
    private volatile Dictionary<string, string>? _rdapCache;
    private readonly Lazy<Dictionary<string, string>> _whoisCache;

    public BootstrapRegistry(HttpClient httpClient, WhoisOptions options)
        : this(httpClient, options, NullLogger<BootstrapRegistry>.Instance)
    {
    }

    public BootstrapRegistry(HttpClient httpClient, WhoisOptions options,
        ILogger<BootstrapRegistry> logger)
    {
        _httpClient = httpClient;
        _options = options;
        _logger = logger;
        _whoisCache = new Lazy<Dictionary<string, string>>(
            () => ParseWhoisBootstrapJson(ResourceReader.GetContent(WhoisResourceName)));
    }

    public async Task<string?> GetRdapBaseUrl(string tld, CancellationToken ct)
    {
        var cache = await EnsureRdapCacheAsync(ct).ConfigureAwait(false);
        cache.TryGetValue(tld, out var url);
        _logger.LogDebug("Bootstrap: RDAP lookup for TLD {Tld}: {Result}", tld, url != null ? "hit" : "miss");
        return url;
    }

    public Task<string?> GetWhoisServer(string tld, CancellationToken ct)
    {
        var data = _whoisCache.Value;
        data.TryGetValue(tld, out var server);
        _logger.LogDebug("Bootstrap: WHOIS lookup for TLD {Tld}: {Result}", tld, server != null ? "hit" : "miss");
        return Task.FromResult<string?>(server);
    }

    public Task Refresh(CancellationToken ct)
    {
        _rdapCache = null;
        _logger.LogInformation("Bootstrap cache cleared");
        return Task.CompletedTask;
    }

    private async Task<Dictionary<string, string>> EnsureRdapCacheAsync(CancellationToken ct)
    {
        var cache = _rdapCache;
        if (cache != null) return cache;

        await _rdapLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Double-check after acquiring lock
            cache = _rdapCache;
            if (cache != null) return cache;

            cache = await FetchRdapBootstrapAsync(ct).ConfigureAwait(false);
            _rdapCache = cache;
            return cache;
        }
        finally
        {
            _rdapLock.Release();
        }
    }

    private async Task<Dictionary<string, string>> FetchRdapBootstrapAsync(CancellationToken ct)
    {
        var url = _options.RdapBootstrapUrl;
        _logger.LogDebug("Bootstrap: fetching RDAP data from {Url}", url);

        var sw = System.Diagnostics.Stopwatch.StartNew();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(_options.TimeoutSeconds));

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.GetAsync(url, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new WhoisException(
                FormattableString.Invariant(
                    $"RDAP bootstrap fetch timed out after {_options.TimeoutSeconds}s: {url}"));
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Bootstrap: fetch failed for {Url}", url);
            throw new WhoisException(
                $"RDAP bootstrap fetch failed for {url}: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var contentType = response.Content.Headers.ContentType?.ToString() ?? "(none)";
                _logger.LogError(
                    "Bootstrap: RDAP fetch returned HTTP {StatusCode}, Content-Type: {ContentType}",
                    (int)response.StatusCode, contentType);
                var statusCode = (int)response.StatusCode;
                throw new WhoisException(
                    FormattableString.Invariant(
                        $"RDAP bootstrap fetch returned HTTP {statusCode} (Content-Type: {contentType}): {url}"));
            }

            var json = await ReadWithSizeLimit(response, MaxResponseSizeChars, cts.Token)
                .ConfigureAwait(false);

            Dictionary<string, string> result;
            try
            {
                result = ParseBootstrapJson(json);
            }
            catch (JsonException ex)
            {
                throw new WhoisException(
                    $"Failed to parse RDAP bootstrap JSON from {url}: {ex.Message}", ex);
            }

            sw.Stop();
            _logger.LogInformation(
                "Bootstrap: loaded {Count} RDAP endpoints in {Duration}ms from {Url}",
                result.Count, sw.ElapsedMilliseconds, url);

            return result;
        }
    }

    private static async Task<string> ReadWithSizeLimit(
        HttpResponseMessage response, int maxChars, CancellationToken ct)
    {
        using var stream = await Net.NetStandardShims.ReadAsStreamAsync(response.Content, ct)
            .ConfigureAwait(false);
        using var reader = new System.IO.StreamReader(stream, System.Text.Encoding.UTF8);
        var buffer = new char[8192];
        var sb = new System.Text.StringBuilder(
            (int)Math.Min(response.Content.Headers.ContentLength ?? 1024, maxChars));
        int charsRead;

        while ((charsRead = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            sb.Append(buffer, 0, charsRead);
            if (sb.Length > maxChars)
            {
                throw new WhoisException(
                    FormattableString.Invariant(
                        $"RDAP bootstrap response exceeds maximum size of {maxChars} characters"));
            }
        }

        return sb.ToString();
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
