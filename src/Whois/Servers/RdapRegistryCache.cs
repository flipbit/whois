using System.Net;
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

#pragma warning disable CA2213 // SemaphoreSlim: singleton lifetime, no Dispose needed
    private readonly SemaphoreSlim _ipv4Lock = new(1, 1);
#pragma warning restore CA2213
    private volatile List<(byte[] Prefix, int Length, string Url)>? _ipv4Cache;
    private long _ipv4CachedAtTicks;

#pragma warning disable CA2213 // SemaphoreSlim: singleton lifetime, no Dispose needed
    private readonly SemaphoreSlim _ipv6Lock = new(1, 1);
#pragma warning restore CA2213
    private volatile List<(byte[] Prefix, int Length, string Url)>? _ipv6Cache;
    private long _ipv6CachedAtTicks;

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

    /// <inheritdoc/>
    public async Task<string?> GetBaseUrl(IPAddress address, CancellationToken ct = default)
    {
        var isIpv4 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var entries = isIpv4
            ? await EnsureIpCacheAsync(isIpv4: true, ct).ConfigureAwait(false)
            : await EnsureIpCacheAsync(isIpv4: false, ct).ConfigureAwait(false);

        return FindLongestMatch(address, entries);
    }

    public void ClearCache()
    {
        Interlocked.Exchange(ref _cachedAtTicks, 0);
        _cache = null;
        Interlocked.Exchange(ref _ipv4CachedAtTicks, 0);
        _ipv4Cache = null;
        Interlocked.Exchange(ref _ipv6CachedAtTicks, 0);
        _ipv6Cache = null;
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
            _logger.LogError("RDAP registry: bootstrap fetch timed out after {Timeout}s for {Url}",
                _options.TimeoutSeconds, url);
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
                _logger.LogError(ex, "RDAP registry: failed to parse bootstrap JSON from {Url}", url);
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

    private async Task<List<(byte[] Prefix, int Length, string Url)>> EnsureIpCacheAsync(bool isIpv4, CancellationToken ct)
    {
        var semaphore = isIpv4 ? _ipv4Lock : _ipv6Lock;

        var cache = isIpv4 ? _ipv4Cache : _ipv6Cache;
        if (cache != null && !IsIpCacheExpired(isIpv4))
            return cache;

        await semaphore.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            cache = isIpv4 ? _ipv4Cache : _ipv6Cache;
            if (cache != null && !IsIpCacheExpired(isIpv4))
                return cache;

            cache = await FetchIpBootstrapAsync(isIpv4, ct).ConfigureAwait(false);
            if (isIpv4)
            {
                _ipv4Cache = cache;
                Interlocked.Exchange(ref _ipv4CachedAtTicks, DateTime.UtcNow.Ticks);
            }
            else
            {
                _ipv6Cache = cache;
                Interlocked.Exchange(ref _ipv6CachedAtTicks, DateTime.UtcNow.Ticks);
            }
            return cache;
        }
        finally
        {
            semaphore.Release();
        }
    }

    private bool IsIpCacheExpired(bool isIpv4)
    {
        var cachedAtTicks = isIpv4
            ? Interlocked.Read(ref _ipv4CachedAtTicks)
            : Interlocked.Read(ref _ipv6CachedAtTicks);
        return DateTime.UtcNow.Ticks - cachedAtTicks >= _options.TldServerCacheDuration.Ticks;
    }

    private async Task<List<(byte[] Prefix, int Length, string Url)>> FetchIpBootstrapAsync(bool isIpv4, CancellationToken ct)
    {
        var url = isIpv4 ? _options.RdapIpv4BootstrapUrl : _options.RdapIpv6BootstrapUrl;
        _logger.LogDebug("RDAP registry: fetching IP bootstrap data from {Url}", url);

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
            _logger.LogError("RDAP registry: IP bootstrap fetch timed out after {Timeout}s for {Url}",
                _options.TimeoutSeconds, url);
            throw new WhoisException(
                FormattableString.Invariant(
                    $"RDAP bootstrap fetch timed out after {_options.TimeoutSeconds}s: {url}"));
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "RDAP registry: IP bootstrap fetch failed for {Url}", url);
            throw new WhoisException(
                $"RDAP bootstrap fetch failed for {url}: {ex.Message}", ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var contentType = response.Content.Headers.ContentType?.ToString() ?? "(none)";
                _logger.LogError(
                    "RDAP registry: IP bootstrap fetch returned HTTP {StatusCode}, Content-Type: {ContentType}",
                    (int)response.StatusCode, contentType);
                var statusCode = (int)response.StatusCode;
                throw new WhoisException(
                    FormattableString.Invariant(
                        $"RDAP bootstrap fetch returned HTTP {statusCode} (Content-Type: {contentType}): {url}"));
            }

            var json = await Net.NetStandardShims.ReadWithSizeLimit(
                    response, _options.MaxRdapBootstrapResponseSize, cts.Token)
                .ConfigureAwait(false);

            List<(byte[] Prefix, int Length, string Url)> result;
            try
            {
                result = ParseIpBootstrapJson(json);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "RDAP registry: failed to parse IP bootstrap JSON from {Url}", url);
                throw new WhoisException(
                    $"Failed to parse RDAP bootstrap JSON from {url}: {ex.Message}", ex);
            }

            sw.Stop();
            _logger.LogInformation(
                "RDAP registry: loaded {Count} IP prefixes in {Duration}ms from {Url}",
                result.Count, sw.ElapsedMilliseconds, url);

            return result;
        }
    }

    /// <summary>
    /// Parses an IANA RDAP IP bootstrap JSON file into a list of CIDR prefix entries.
    /// Only HTTPS URLs are accepted; entries with no HTTPS URL are skipped.
    /// </summary>
    internal static List<(byte[] Prefix, int Length, string Url)> ParseIpBootstrapJson(string json)
    {
        var result = new List<(byte[] Prefix, int Length, string Url)>();
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty(BootstrapServicesProperty, out var services)) return result;

        foreach (var service in services.EnumerateArray())
        {
            var entries = service.EnumerateArray().ToArray();
            if (entries.Length < 2) continue;

            var prefixes = entries[0];
            var urls = entries[1];

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

            foreach (var prefix in prefixes.EnumerateArray())
            {
                var cidr = prefix.GetString();
                if (cidr == null) continue;

                var slashIndex = cidr.IndexOf('/', StringComparison.Ordinal);
                if (slashIndex < 0) continue;

                if (!IPAddress.TryParse(cidr[..slashIndex], out var prefixAddr)) continue;
                if (!int.TryParse(cidr[(slashIndex + 1)..], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var prefixLen)) continue;

                result.Add((prefixAddr.GetAddressBytes(), prefixLen, baseUrl));
            }
        }

        return result;
    }

    private static string? FindLongestMatch(IPAddress address, List<(byte[] Prefix, int Length, string Url)> entries)
    {
        var addrBytes = address.GetAddressBytes();
        string? bestUrl = null;
        var bestLen = -1;

        foreach (var (prefix, length, url) in entries)
        {
            if (prefix.Length != addrBytes.Length) continue;
            if (MatchesPrefix(addrBytes, prefix, length) && length > bestLen)
            {
                bestLen = length;
                bestUrl = url;
            }
        }

        return bestUrl;
    }

    private static bool MatchesPrefix(byte[] address, byte[] prefix, int prefixLength)
    {
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            if (address[i] != prefix[i]) return false;
        }

        if (remainingBits > 0)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((address[fullBytes] & mask) != (prefix[fullBytes] & mask)) return false;
        }

        return true;
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
