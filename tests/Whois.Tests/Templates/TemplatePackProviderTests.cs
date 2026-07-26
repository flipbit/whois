using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Whois.Templates;

namespace Whois.Tests.Templates;

/// <summary>
/// Tests for TemplatePackProvider.
///
/// All HTTP calls are intercepted via a custom DelegatingHandler.
/// Signature verification is injected as a Func so we can test pipeline logic
/// independently of the real Ed25519 verify path.
/// </summary>
public class TemplatePackProviderTests : IDisposable
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private const string Version1 = "2026.07.12.1";
    private const string Version2 = "2026.07.13.1";   // newer
    private const string VersionOld = "2026.01.01.1"; // older
    private const string DefaultUrl = "https://api.github.com/repos/flipbit/whois/releases/latest";

    private readonly string _tempDir;
    private readonly CacheDirectoryManager _cache;
    private readonly TemplateUpdateState _state;

    public TemplatePackProviderTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "whois-provider-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _cache = new CacheDirectoryManager(_tempDir, NullLogger<CacheDirectoryManager>.Instance);
        _state = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    /// <summary>Builds a minimal release JSON string.</summary>
    private static string BuildReleaseJson(string version, string zipUrl, string sigUrl) =>
        JsonSerializer.Serialize(new
        {
            tag_name = $"templates-{version}",
            assets = new[]
            {
                new { name = "templates.zip", browser_download_url = zipUrl },
                new { name = "templates.zip.minisig", browser_download_url = sigUrl },
            }
        });

    /// <summary>Builds an in-memory zip containing a single file.</summary>
    private static byte[] BuildZip(string entryName = "whois.example.com/example/Found.txt",
                                    string entryContent = "name: {{ DomainName }}")
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry(entryName);
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write(entryContent);
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Creates a handler that returns a fixed sequence of responses for successive calls.
    /// </summary>
    private static HttpMessageHandler SequentialHandler(params (HttpStatusCode status, string body)[] responses)
    {
        var queue = new Queue<(HttpStatusCode, string)>(responses);
        return new FuncHandler(req =>
        {
            if (!queue.TryDequeue(out var response))
                throw new InvalidOperationException("No more responses in queue");
            var (status, body) = response;
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8),
            });
        });
    }

    /// <summary>Handler that throws on every call.</summary>
    private static HttpMessageHandler ThrowingHandler(Exception ex) =>
        new FuncHandler(_ => throw ex);

    /// <summary>Handler that returns a large body (>10MB) for the zip download.</summary>
    private static HttpMessageHandler OversizedZipHandler(string releaseJson)
    {
        var callCount = 0;
        return new FuncHandler(req =>
        {
            callCount++;
            if (callCount == 1)
            {
                // First call: release metadata
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(releaseJson, Encoding.UTF8),
                });
            }

            // Second call: the zip  -  11 MB of zeros
            var oversized = new byte[11 * 1024 * 1024];
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(oversized),
            });
        });
    }

    private TemplatePackProvider MakeProvider(
        HttpMessageHandler handler,
        Func<byte[], string, bool>? signatureVerifier = null,
        string? currentVersion = null,
        string? releaseUrl = null)
    {
        if (currentVersion != null)
            _state.RecordSuccess(currentVersion, DateTimeOffset.UtcNow - TimeSpan.FromDays(2));

        var options = new WhoisOptions
        {
            TemplateReleaseUrl = releaseUrl,
        };

        var httpClient = new HttpClient(handler) { BaseAddress = null };
        return new TemplatePackProvider(
            httpClient: httpClient,
            options: options,
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: _state,
            signatureVerifier: signatureVerifier ?? ((_, _) => true));
    }

    // -------------------------------------------------------------------------
    // FuncHandler helper
    // -------------------------------------------------------------------------

    private sealed class FuncHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _func;
        public FuncHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> func) => _func = func;
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => _func(request);
    }

    // =========================================================================
    // CheckForUpdate  -  Happy path
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_Success_UpdatesAndReturnsUpdated()
    {
        var zipBytes = BuildZip();
        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var callOrder = new List<string>();
        var handler = new FuncHandler(req =>
        {
            if (req.RequestUri!.ToString().EndsWith("releases/latest", StringComparison.Ordinal)
                || req.RequestUri.ToString() == "https://example.com/releases/latest")
            {
                callOrder.Add("metadata");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(releaseJson, Encoding.UTF8),
                });
            }

            if (req.RequestUri.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
            {
                callOrder.Add("sig");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("fake-sig", Encoding.UTF8),
                });
            }

            callOrder.Add("zip");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(zipBytes),
            });
        });

        var provider = MakeProvider(handler, currentVersion: Version1);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Updated, result.Outcome);
        Assert.Equal(Version2, result.Version);
        Assert.Null(result.Error);
        Assert.Equal(Version2, provider.Status.CurrentVersion);
    }

    // =========================================================================
    // CheckForUpdate  -  AlreadyUpToDate
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_AlreadyUpToDate_ReturnsAlreadyUpToDate()
    {
        var releaseJson = BuildReleaseJson(
            Version1,                              // same version as current
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var httpCallCount = 0;
        var handler = new FuncHandler(req =>
        {
            httpCallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            });
        });

        var provider = MakeProvider(handler, currentVersion: Version1);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.AlreadyUpToDate, result.Outcome);
        Assert.Equal(1, httpCallCount); // only metadata was fetched
    }

    // =========================================================================
    // CheckForUpdate  -  Downgrade rejected
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_DowngradeRejected_ReturnsAlreadyUpToDate()
    {
        var releaseJson = BuildReleaseJson(
            VersionOld,                            // older than current
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var zipCallCount = 0;
        var handler = new FuncHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
                zipCallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            });
        });

        var provider = MakeProvider(handler, currentVersion: Version1);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.AlreadyUpToDate, result.Outcome);
        Assert.Equal(0, zipCallCount); // zip was never downloaded
    }

    // =========================================================================
    // CheckForUpdate  -  HTTP errors
    // =========================================================================

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task CheckForUpdate_HttpError_ReturnsFailed(HttpStatusCode status)
    {
        var handler = new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(status)));

        var provider = MakeProvider(handler);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    [Fact]
    public async Task CheckForUpdate_NetworkError_ReturnsFailed()
    {
        var handler = ThrowingHandler(new HttpRequestException("Connection refused"));

        var provider = MakeProvider(handler);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    [Fact]
    public async Task CheckForUpdate_NonHttpsUrl_ReturnsFailed()
    {
        var handler = new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));

        var provider = MakeProvider(handler, releaseUrl: "http://example.com/releases/latest");

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    [Fact]
    public async Task CheckForUpdate_ResponseTooLarge_ReturnsFailed()
    {
        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var provider = MakeProvider(OversizedZipHandler(releaseJson), currentVersion: Version1);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    // =========================================================================
    // CheckForUpdate  -  Signature failure
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_SignatureInvalid_ReturnsFailed()
    {
        var zipBytes = BuildZip();
        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var handler = new FuncHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("bad-sig", Encoding.UTF8),
                });
            }

            if (req.RequestUri.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(zipBytes),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            });
        });

        // Inject a verifier that always rejects
        var provider = MakeProvider(handler,
            signatureVerifier: (_, _) => false,
            currentVersion: Version1);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    // =========================================================================
    // CheckForUpdate  -  Concurrency
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_ConcurrentCalls_SecondReturnsSkipped()
    {
        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var tcs = new TaskCompletionSource<bool>();
        var metadataCallCount = 0;

        var handler = new FuncHandler(async req =>
        {
            if (req.RequestUri!.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("fake-sig", Encoding.UTF8),
                };
            }

            if (req.RequestUri.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(BuildZip()),
                };
            }

            // metadata  -  first call blocks until we release the gate
            Interlocked.Increment(ref metadataCallCount);
            await tcs.Task;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            };
        });

        var provider = MakeProvider(handler, currentVersion: Version1);

        // Fire first call  -  it will block inside the handler
        var first = provider.CheckForUpdate();

        // Give first call time to enter the HTTP handler
        await Task.Delay(50);

        // Second call should return Skipped immediately
        var second = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Skipped, second.Outcome);

        // Unblock first call
        tcs.SetResult(true);
        var firstResult = await first;

        Assert.Equal(TemplateUpdateOutcome.Updated, firstResult.Outcome);
        Assert.Equal(1, metadataCallCount);
    }

    // =========================================================================
    // CheckForUpdate  -  Never throws
    // =========================================================================

    [Theory]
    [InlineData("HttpRequestException")]
    [InlineData("TaskCanceledException")]
    [InlineData("InvalidOperationException")]
    public async Task CheckForUpdate_NeverThrows_ReturnsFailedOnException(string exceptionType)
    {
        var ex = exceptionType switch
        {
            "HttpRequestException" => (Exception)new HttpRequestException("boom"),
            "TaskCanceledException" => new TaskCanceledException("boom"),
            _ => new InvalidOperationException("boom"),
        };

        var handler = ThrowingHandler(ex);
        var provider = MakeProvider(handler);

        var result = await provider.CheckForUpdate();

        // Must not throw  -  must return Failed
        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    // =========================================================================
    // CheckForUpdate  -  Backoff
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_InBackoff_ReturnsSkipped()
    {
        // Record a failure just now  -  backoff starts at 1 hour
        _state.RecordFailure(DateTimeOffset.UtcNow);
        _state.Save();

        var httpCallCount = 0;
        var handler = new FuncHandler(req =>
        {
            httpCallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var provider = MakeProvider(handler);
        var newState = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        newState.Load();

        var providerWithState = new TemplatePackProvider(
            httpClient: new HttpClient(handler),
            options: new WhoisOptions(),
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: newState,
            signatureVerifier: (_, _) => true);

        var result = await providerWithState.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Skipped, result.Outcome);
        Assert.Equal(0, httpCallCount);
    }

    [Fact]
    public async Task CheckForUpdate_AfterBackoffExpires_Retries()
    {
        // Record a failure in the past, beyond the 1-hour backoff
        _state.RecordFailure(DateTimeOffset.UtcNow - TimeSpan.FromHours(2));
        _state.Save();

        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var httpCallCount = 0;
        var handler = new FuncHandler(req =>
        {
            httpCallCount++;
            if (req.RequestUri!.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("sig") });
            if (req.RequestUri.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(BuildZip()) });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(releaseJson) });
        });

        var newState = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        newState.Load();

        var provider = new TemplatePackProvider(
            httpClient: new HttpClient(handler),
            options: new WhoisOptions(),
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: newState,
            signatureVerifier: (_, _) => true);

        var result = await provider.CheckForUpdate();

        Assert.True(httpCallCount > 0, "Expected HTTP calls to be made after backoff expired");
    }

    // =========================================================================
    // CheckForUpdate  -  Disk failure disables for session
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_DiskFailure_DisablesForSession()
    {
        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        // Use a corrupt (non-zip) payload so ExtractPack returns false, triggering session disable
        var handler = new FuncHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("sig") });
            if (req.RequestUri.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes("NOT A ZIP FILE")),
                });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(releaseJson) });
        });

        var provider = new TemplatePackProvider(
            httpClient: new HttpClient(handler),
            options: new WhoisOptions(),
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: _state,
            signatureVerifier: (_, _) => true);

        // First attempt  -  will fail due to extraction failure
        var firstResult = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, firstResult.Outcome);
        Assert.False(provider.Status.AutoUpdateEnabled);

        // Second call should be skipped immediately (session disabled)
        var secondResult = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Skipped, secondResult.Outcome);
    }

    // =========================================================================
    // GetCachedTemplatePath
    // =========================================================================

    [Fact]
    public void GetCachedTemplatePath_ReturnsNull_WhenNoCacheExists()
    {
        var provider = MakeProvider(new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));

        var path = provider.GetCachedTemplatePath("whois.nic.example");

        Assert.Null(path);
    }

    [Fact]
    public void GetCachedTemplatePath_ReturnsPath_WhenCacheExists()
    {
        // Create the directory structure that CacheDirectoryManager.GetServerDirectory checks
        var serverDir = Path.Combine(_tempDir, "current", "whois.nic.example");
        Directory.CreateDirectory(serverDir);

        var provider = MakeProvider(new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));

        var path = provider.GetCachedTemplatePath("whois.nic.example");

        Assert.NotNull(path);
        Assert.True(Directory.Exists(path));
    }

    // =========================================================================
    // Status property
    // =========================================================================

    [Fact]
    public void Status_DefaultState_ReturnsEmbeddedSource()
    {
        var provider = MakeProvider(new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));

        var status = provider.Status;

        Assert.Equal(TemplateSource.Embedded, status.Source);
        Assert.Equal("embedded", status.CurrentVersion);
    }

    [Fact]
    public void Status_WithCachedVersion_ReturnsCachedSource()
    {
        var provider = MakeProvider(
            new FuncHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))),
            currentVersion: Version1);

        var status = provider.Status;

        Assert.Equal(TemplateSource.Cached, status.Source);
        Assert.Equal(Version1, status.CurrentVersion);
    }

    // =========================================================================
    // CheckForUpdate  -  Custom URL warning (smoke test)
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_CustomUrl_DoesNotThrow()
    {
        var releaseJson = BuildReleaseJson(
            Version2,
            "https://custom.example.com/templates.zip",
            "https://custom.example.com/templates.zip.minisig");

        var handler = new FuncHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("sig") });
            if (req.RequestUri.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(BuildZip()) });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(releaseJson) });
        });

        var provider = MakeProvider(handler,
            currentVersion: Version1,
            releaseUrl: "https://custom.example.com/releases/latest");

        // Should not throw  -  custom URL warning is just a log event
        var result = await provider.CheckForUpdate();

        // We accept Updated or any outcome  -  just no exception
        Assert.NotNull(result);
    }

    // =========================================================================
    // CheckForUpdate  -  Partial failure, previous cache intact
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_ExtractionFails_PreviousCacheIntact()
    {
        // Pre-populate a "current" directory to simulate existing cache
        var existingServerDir = Path.Combine(_tempDir, "current", "whois.existing.test");
        Directory.CreateDirectory(existingServerDir);
        File.WriteAllText(Path.Combine(existingServerDir, "Found.txt"), "name: {{ DomainName }}");

        var releaseJson = BuildReleaseJson(
            Version2,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        // Return an invalid (non-zip) zip body to trigger extraction failure
        var handler = new FuncHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri.EndsWith(".minisig", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("sig") });
            if (req.RequestUri.AbsoluteUri.EndsWith(".zip", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes("NOT A ZIP FILE")),
                });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(releaseJson) });
        });

        var provider = MakeProvider(handler, currentVersion: Version1);
        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
        // State version should remain unchanged (Version1), not updated to Version2
        Assert.NotEqual(Version2, provider.Status.CurrentVersion);
    }

    // =========================================================================
    // CheckForUpdate  -  Unparseable version in release JSON
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_UnparseableVersion_ReturnsFailed()
    {
        // tag_name that doesn't produce a parseable version
        var releaseJson = JsonSerializer.Serialize(new
        {
            tag_name = "not-a-version",
            assets = Array.Empty<object>()
        });

        var handler = new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            }));

        var provider = MakeProvider(handler);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, result.Outcome);
    }

    // =========================================================================
    // CheckForUpdate  -  DisabledForSession skips immediately
    // =========================================================================

    [Fact]
    public async Task CheckForUpdate_DisabledForSession_ReturnsSkipped()
    {
        _state.DisabledForSession = true;

        var httpCallCount = 0;
        var handler = new FuncHandler(req =>
        {
            httpCallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var provider = MakeProvider(handler);

        var result = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Skipped, result.Outcome);
        Assert.Equal(0, httpCallCount);
    }
}
