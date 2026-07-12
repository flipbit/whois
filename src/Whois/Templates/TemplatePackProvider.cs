using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Whois.Security;

namespace Whois.Templates;

/// <summary>
/// Downloads, verifies, and caches template packs from a GitHub releases endpoint.
///
/// Singleton. Serialises concurrent <see cref="CheckForUpdate"/> calls via an
/// <c>Interlocked</c> guard — the second concurrent caller receives
/// <see cref="TemplateUpdateOutcome.Skipped"/> immediately.
/// </summary>
// MA0182: consumed by WhoisLookup (Task 8) — suppress until then.
#pragma warning disable MA0182
internal sealed class TemplatePackProvider : ITemplatePackProvider
#pragma warning restore MA0182
{
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private const string DefaultReleaseUrl =
        "https://api.github.com/repos/flipbit/whois/releases/latest";

    // RFC 8032 Vector 1 test public key — Plan 4 will replace with production key.
    private const string EmbeddedPublicKey =
        "untrusted comment: minisign public key test\n" +
        "RWQBAgMEBQYHCNdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

    private const long MaxDownloadBytes = 10L * 1024 * 1024; // 10 MB
    private const long MaxSigBytes = 4096;

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    private readonly HttpClient _httpClient;
    private readonly WhoisOptions _options;
    private readonly ILogger<TemplatePackProvider> _logger;
    private readonly CacheDirectoryManager _cache;
    private readonly TemplateUpdateState _state;
    private readonly Func<byte[], string, bool> _signatureVerifier;

    private int _checkInProgress;
    private bool _customUrlWarningLogged;

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    private static readonly Lazy<HttpClient> DefaultHttpClient = new(() =>
    {
        var handler = new HttpClientHandler
        {
            MaxAutomaticRedirections = 5,
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    });

    /// <summary>
    /// Constructor for DI use — takes a named <see cref="HttpClient"/> created by
    /// the factory (avoids singleton-captures-handler anti-pattern).
    /// </summary>
    public TemplatePackProvider(
        IHttpClientFactory httpClientFactory,
        IOptions<WhoisOptions> options,
        ILogger<TemplatePackProvider> logger,
        CacheDirectoryManager cache,
        TemplateUpdateState state)
        : this(
            httpClientFactory.CreateClient("TemplatePackProvider"),
            options.Value,
            logger,
            cache,
            state,
            signatureVerifier: null)
    {
    }

    /// <summary>
    /// Constructor for non-DI use — uses a shared static <see cref="HttpClient"/>.
    /// </summary>
    internal TemplatePackProvider(WhoisOptions options, ILogger<TemplatePackProvider> logger,
                                  CacheDirectoryManager cache, TemplateUpdateState state)
        : this(DefaultHttpClient.Value, options, logger, cache, state)
    {
    }

    /// <summary>
    /// Constructor for non-DI use and testing — accepts a pre-built <see cref="HttpClient"/>.
    /// </summary>
    internal TemplatePackProvider(
        HttpClient httpClient,
        WhoisOptions options,
        ILogger<TemplatePackProvider> logger,
        CacheDirectoryManager cache,
        TemplateUpdateState state,
        Func<byte[], string, bool>? signatureVerifier = null)
    {
        _httpClient = httpClient;
        _options = options;
        _logger = logger;
        _cache = cache;
        _state = state;
        _signatureVerifier = signatureVerifier
            ?? ((content, sig) => MinisignVerifier.Verify(content, sig, EmbeddedPublicKey));
    }

    // -------------------------------------------------------------------------
    // ITemplatePackProvider
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public TemplateStatus Status
    {
        get
        {
            var version = _state.CurrentVersion;
            var source = version != null ? TemplateSource.Cached : TemplateSource.Embedded;
            var displayVersion = version ?? "embedded";
            var interval = _options.TemplateUpdateCheckInterval;

            return new TemplateStatus(
                CurrentVersion: displayVersion,
                Source: source,
                LastCheckTime: _state.LastCheckTime,
                NextCheckTime: _state.GetNextEligibleTime(interval),
                LastError: _state.LastSuccess || _state.ConsecutiveFailures == 0
                    ? null
                    : string.Format(
                        CultureInfo.InvariantCulture,
                        "Last check failed ({0} consecutive failures)",
                        _state.ConsecutiveFailures),
                AutoUpdateEnabled: !_state.DisabledForSession);
        }
    }

    /// <inheritdoc/>
    public string? GetCachedTemplatePath(string server)
        => _cache.GetServerDirectory(server);

    /// <inheritdoc/>
#pragma warning disable CA1031 // Never propagate — return Failed on any exception
    public async Task<TemplateUpdateResult> CheckForUpdate(CancellationToken cancellationToken = default)
    {
        // ── Concurrency guard ─────────────────────────────────────────────────
        if (Interlocked.CompareExchange(ref _checkInProgress, 1, 0) != 0)
        {
            _logger.LogDebug("Template update check skipped: another check is already in progress");
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Skipped,
                Version: Status.CurrentVersion,
                Error: null);
        }

        try
        {
            return await RunCheckAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Template update check failed for {TemplateUpdateUrl}: {ExceptionType} — {ExceptionMessage}",
                _options.TemplateReleaseUrl ?? DefaultReleaseUrl,
                ex.GetType().Name,
                ex.Message);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _checkInProgress, 0);
        }
    }
#pragma warning restore CA1031

    // -------------------------------------------------------------------------
    // Private — main pipeline
    // -------------------------------------------------------------------------

    private async Task<TemplateUpdateResult> RunCheckAsync(CancellationToken cancellationToken)
    {
        // ── Session disable check ─────────────────────────────────────────────
        if (_state.DisabledForSession)
        {
            _logger.LogDebug("Template update check skipped: auto-update disabled for this session");
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Skipped,
                Version: Status.CurrentVersion,
                Error: null);
        }

        // ── Eligibility / backoff check ───────────────────────────────────────
        var interval = _options.TemplateUpdateCheckInterval;
        if (!_state.IsEligibleForCheck(interval))
        {
            var next = _state.GetNextEligibleTime(interval);
            if (_state.LastSuccess || _state.ConsecutiveFailures == 0)
            {
                _logger.LogDebug(
                    "Template update check skipped, last checked {LastCheckTime}, next eligible at {NextCheckTime}",
                    _state.LastCheckTime,
                    next);
            }
            else
            {
                _logger.LogDebug(
                    "Template update check skipped, next eligible at {NextCheckTime}, last error: {LastErrorReason}",
                    next,
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "{0} consecutive failures",
                        _state.ConsecutiveFailures));
            }

            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Skipped,
                Version: Status.CurrentVersion,
                Error: null);
        }

        // ── Resolve and validate the release URL ─────────────────────────────
        var releaseUrl = _options.TemplateReleaseUrl ?? DefaultReleaseUrl;

        if (!string.IsNullOrEmpty(_options.TemplateReleaseUrl) && !_customUrlWarningLogged)
        {
            _customUrlWarningLogged = true;
            _logger.LogWarning("Using custom template release URL: {TemplateUpdateUrl}", releaseUrl);
        }

        if (!Uri.TryCreate(releaseUrl, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            var scheme = Uri.TryCreate(releaseUrl, UriKind.Absolute, out var u) ? u.Scheme : "unknown";
            _logger.LogWarning(
                "Template update URL rejected: scheme must be https, got {UrlScheme} for {TemplateUpdateUrl}",
                scheme,
                releaseUrl);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: string.Format(CultureInfo.InvariantCulture, "URL scheme must be https, got '{0}'", scheme));
        }

        // ── Fetch release metadata ────────────────────────────────────────────
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(30));

        string metadataJson;
        try
        {
            using var metaResponse = await _httpClient
                .GetAsync(releaseUrl, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                .ConfigureAwait(false);

            if (!metaResponse.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Template update check failed for {TemplateUpdateUrl}, attempted version {AttemptedVersion}, " +
                    "HTTP status {HttpStatus}, current version {CurrentVersion}",
                    releaseUrl,
                    "unknown",
                    (int)metaResponse.StatusCode,
                    Status.CurrentVersion);
                RecordFailure();
                return new TemplateUpdateResult(
                    Outcome: TemplateUpdateOutcome.Failed,
                    Version: null,
                    Error: string.Format(CultureInfo.InvariantCulture, "HTTP {0}", (int)metaResponse.StatusCode));
            }

#if NETSTANDARD2_0
            metadataJson = await metaResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
#else
            metadataJson = await metaResponse.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
#endif
        }
#pragma warning disable CA1031 // Catching broad exception to guarantee "never throws" contract
        catch (Exception ex)
        {
            _logger.LogWarning(
                "Template update check failed for {TemplateUpdateUrl}: {ExceptionType} — {ExceptionMessage}",
                releaseUrl,
                ex.GetType().Name,
                ex.Message);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: ex.Message);
        }
#pragma warning restore CA1031

        // ── Parse version from metadata ───────────────────────────────────────
        if (!TryParseReleaseMetadata(
                metadataJson,
                out var offeredVersion,
                out var zipDownloadUrl,
                out var sigDownloadUrl))
        {
            _logger.LogWarning(
                "Template update check failed for {TemplateUpdateUrl}: could not parse release metadata",
                releaseUrl);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: "Could not parse release metadata");
        }

        // ── Version comparison ────────────────────────────────────────────────
        var currentVersion = _state.CurrentVersion;
        if (currentVersion != null
            && TemplateVersion.TryParse(currentVersion, out var currentComponents)
            && TemplateVersion.TryParse(offeredVersion, out var offeredComponents))
        {
            var cmp = TemplateVersion.Compare(offeredComponents!, currentComponents!);
            if (cmp < 0)
            {
                _logger.LogWarning(
                    "Template pack downgrade rejected: server offered {OfferedVersion}, " +
                    "current version is {CurrentVersion} via {TemplateUpdateUrl}",
                    offeredVersion,
                    currentVersion,
                    releaseUrl);
                return new TemplateUpdateResult(
                    Outcome: TemplateUpdateOutcome.AlreadyUpToDate,
                    Version: currentVersion,
                    Error: null);
            }

            if (cmp == 0)
            {
                RecordSuccess(currentVersion);
                return new TemplateUpdateResult(
                    Outcome: TemplateUpdateOutcome.AlreadyUpToDate,
                    Version: currentVersion,
                    Error: null);
            }
        }

        // ── Download zip ──────────────────────────────────────────────────────
        byte[] zipBytes;
        try
        {
            zipBytes = await DownloadWithSizeLimitAsync(zipDownloadUrl, MaxDownloadBytes, cts.Token)
                .ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Catching broad exception to guarantee "never throws" contract
        catch (Exception ex)
        {
            _logger.LogWarning(
                "Template update check failed for {TemplateUpdateUrl}: {ExceptionType} — {ExceptionMessage}",
                releaseUrl,
                ex.GetType().Name,
                ex.Message);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: ex.Message);
        }
#pragma warning restore CA1031

        // ── Download .sig ─────────────────────────────────────────────────────
        string sigText;
        try
        {
            var sigBytes = await DownloadWithSizeLimitAsync(sigDownloadUrl, MaxSigBytes, cts.Token)
                .ConfigureAwait(false);
            sigText = Encoding.UTF8.GetString(sigBytes);
        }
#pragma warning disable CA1031 // Catching broad exception to guarantee "never throws" contract
        catch (Exception ex)
        {
            _logger.LogWarning(
                "Template update check failed for {TemplateUpdateUrl}: {ExceptionType} — {ExceptionMessage}",
                releaseUrl,
                ex.GetType().Name,
                ex.Message);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: ex.Message);
        }
#pragma warning restore CA1031

        // ── Verify signature ──────────────────────────────────────────────────
        if (!_signatureVerifier(zipBytes, sigText))
        {
            _logger.LogWarning(
                "Template pack signature verification failed for {TemplateUpdateUrl}, " +
                "version {AttemptedVersion} — discarding pack",
                releaseUrl,
                offeredVersion);
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: "Signature verification failed");
        }

        // ── Extract pack ──────────────────────────────────────────────────────
        if (!_cache.ExtractPack(zipBytes, "current"))
        {
            _logger.LogWarning(
                "Template pack extraction failed for {TemplateUpdateUrl}, version {AttemptedVersion}: {RejectionReason}",
                releaseUrl,
                offeredVersion,
                "ExtractPack returned false");

            DisableForSession("ExtractionFailed", "ExtractPack returned false");
            RecordFailure();
            return new TemplateUpdateResult(
                Outcome: TemplateUpdateOutcome.Failed,
                Version: null,
                Error: "Extraction failed");
        }

        // ── Record success ────────────────────────────────────────────────────
        var previousVersion = Status.CurrentVersion;
        RecordSuccess(offeredVersion);

        _logger.LogInformation(
            "Template pack updated from {PreviousVersion} to {NewVersion} via {TemplateUpdateUrl}",
            previousVersion,
            offeredVersion,
            releaseUrl);

        return new TemplateUpdateResult(
            Outcome: TemplateUpdateOutcome.Updated,
            Version: offeredVersion,
            Error: null);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private async Task<byte[]> DownloadWithSizeLimitAsync(
        string url, long maxBytes, CancellationToken cancellationToken)
    {
        using var response = await _httpClient
            .GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

#if NETSTANDARD2_0
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#endif
        using var ms = new MemoryStream();

        var buffer = new byte[81920];
        int bytesRead;
        long totalRead = 0;

        while ((bytesRead = await stream
            .ReadAsync(buffer, 0, buffer.Length, cancellationToken)
            .ConfigureAwait(false)) > 0)
        {
            totalRead += bytesRead;
            if (totalRead > maxBytes)
            {
                throw new InvalidOperationException(
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "Response exceeded size limit of {0} bytes",
                        maxBytes));
            }

            ms.Write(buffer, 0, bytesRead);
        }

        return ms.ToArray();
    }

    private static bool TryParseReleaseMetadata(
        string json,
        out string version,
        out string zipUrl,
        out string sigUrl)
    {
        version = string.Empty;
        zipUrl = string.Empty;
        sigUrl = string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // tag_name format: "templates-YYYY.MM.DD.N"
            if (!root.TryGetProperty("tag_name", out var tagNameEl))
                return false;

            var tagName = tagNameEl.GetString() ?? string.Empty;
            const string prefix = "templates-";
            if (!tagName.StartsWith(prefix, StringComparison.Ordinal))
                return false;

            var candidate = tagName.Substring(prefix.Length);
            if (!TemplateVersion.TryParse(candidate, out _))
                return false;

            version = candidate;

            if (!root.TryGetProperty("assets", out var assetsEl))
                return false;

            foreach (var asset in assetsEl.EnumerateArray())
            {
                if (!asset.TryGetProperty("name", out var nameEl)) continue;
                if (!asset.TryGetProperty("browser_download_url", out var urlEl)) continue;

                var name = nameEl.GetString() ?? string.Empty;
                var url = urlEl.GetString() ?? string.Empty;

                if (string.Equals(name, "templates.zip", StringComparison.Ordinal))
                    zipUrl = url;
                else if (string.Equals(name, "templates.zip.minisig", StringComparison.Ordinal))
                    sigUrl = url;
            }

            return !string.IsNullOrEmpty(zipUrl) && !string.IsNullOrEmpty(sigUrl);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private void RecordSuccess(string version)
    {
        _state.RecordSuccess(version, DateTimeOffset.UtcNow);
        _state.Save();
    }

    private void RecordFailure()
    {
        _state.RecordFailure(DateTimeOffset.UtcNow);
        _state.Save();
    }

    private void DisableForSession(string errorType, string errorMessage)
    {
        _state.DisabledForSession = true;
        _logger.LogWarning(
            "Auto-update disabled: cache directory {CacheDirectory} is not writable — {ErrorType}: {ErrorMessage}",
            _cache.BaseDirectory,
            errorType,
            errorMessage);
    }
}
