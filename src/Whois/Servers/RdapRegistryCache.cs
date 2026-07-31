using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Whois.Servers;

/// <summary>
/// Fetches and caches RDAP bootstrap data from IANA.
/// The full TLD-to-URL mapping is fetched on first use and cached until
/// <see cref="WhoisOptions.TldServerCacheDuration"/> expires or <see cref="ClearCache"/> is called.
/// </summary>
public class RdapRegistryCache : IRdapRegistryCache
{
    private const string BootstrapServicesProperty = "services";

    private readonly HttpClient _httpClient;
    private readonly WhoisOptions _options;
    private readonly ILogger<RdapRegistryCache> _logger;

#pragma warning disable CA2213 // SemaphoreSlim: singleton lifetime, no Dispose needed
    private readonly SemaphoreSlim _lock = new(1, 1);
#pragma warning restore CA2213
    private volatile Dictionary<string, string>? _cache;
    private long _cachedAtTicks;

    public RdapRegistryCache(HttpClient httpClient, WhoisOptions options)
        : this(httpClient, options, NullLogger<RdapRegistryCache>.Instance)
    {
    }

    public RdapRegistryCache(HttpClient httpClient, WhoisOptions options,
        ILogger<RdapRegistryCache> logger)
    {
        _httpClient = httpClient;
        _options = options;
        _logger = logger;
    }

    public async Task<string?> GetBaseUrl(string tld, CancellationToken ct = default)
    {
        var cache = await EnsureCacheAsync(ct).ConfigureAwait(false);
        cache.TryGetValue(tld, out var url);
        _logger.LogDebug("RDAP registry: lookup for TLD {Tld}: {Result}", tld, url != null ? "hit" : "miss");
        return url;
    }

    public void ClearCache()
    {
        Interlocked.Exchange(ref _cachedAtTicks, 0);
        _cache = null;
        _logger.LogInformation("RDAP registry cache cleared");
    }

    private async Task<Dictionary<string, string>> EnsureCacheAsync(CancellationToken ct)
    {
        var cache = _cache;
        if (cache != null && DateTime.UtcNow.Ticks - Interlocked.Read(ref _cachedAtTicks) < _options.TldServerCacheDuration.Ticks)
            return cache;

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            cache = _cache;
            if (cache != null && DateTime.UtcNow.Ticks - Interlocked.Read(ref _cachedAtTicks) < _options.TldServerCacheDuration.Ticks)
                return cache;

            cache = await FetchBootstrapAsync(ct).ConfigureAwait(false);
            _cache = cache;
            Interlocked.Exchange(ref _cachedAtTicks, DateTime.UtcNow.Ticks);
            return cache;
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<Dictionary<string, string>> FetchBootstrapAsync(CancellationToken ct)
    {
        var url = _options.RdapBootstrapUrl;
        _logger.LogDebug("RDAP registry: fetching bootstrap data from {Url}", url);

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
            _logger.LogError(ex, "RDAP registry: fetch failed for {Url}", url);
            throw new WhoisException(
                $"RDAP bootstrap fetch failed for {url}: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var contentType = response.Content.Headers.ContentType?.ToString() ?? "(none)";
                _logger.LogError(
                    "RDAP registry: fetch returned HTTP {StatusCode}, Content-Type: {ContentType}",
                    (int)response.StatusCode, contentType);
                var statusCode = (int)response.StatusCode;
                throw new WhoisException(
                    FormattableString.Invariant(
                        $"RDAP bootstrap fetch returned HTTP {statusCode} (Content-Type: {contentType}): {url}"));
            }

            var json = await Net.NetStandardShims.ReadWithSizeLimit(
                    response, _options.MaxRdapBootstrapResponseSize, cts.Token)
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
                "RDAP registry: loaded {Count} endpoints in {Duration}ms from {Url}",
                result.Count, sw.ElapsedMilliseconds, url);

            return result;
        }
    }

    /// <summary>
    /// Parses an IANA RDAP bootstrap JSON file, returning a map of TLD to HTTPS base URL.
    /// Only HTTPS URLs are accepted; entries with no HTTPS URL are skipped.
    /// </summary>
    internal static Dictionary<string, string> ParseBootstrapJson(string json)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty(BootstrapServicesProperty, out var services)) return result;

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
}
