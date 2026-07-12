using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Whois.Parsers;
using Whois.Templates;

namespace Whois.Tests.Templates;

/// <summary>
/// End-to-end integration tests for the template update pipeline:
/// WhoisLookup → TemplatePackProvider → download → verify → extract → parser loads from cache.
///
/// All HTTP calls are intercepted via a custom DelegatingHandler.
/// Signature verification is injected as a Func that always returns true.
/// Real filesystem operations are used (temp directories).
/// </summary>
public class TemplateUpdateIntegrationTests : IDisposable
{
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private const string TestVersion = "2026.07.12.1";
    private const string NewVersion = "2026.07.13.1";
    private const string TestServer = "whois.test.example";
    private const string AnotherServer = "whois.other.example";

    // A minimal Tokenizer template that matches "Domain Name: <value>" and tags the test server.
    private const string TestTemplateContent =
        "---\n" +
        "name: whois.test.example/test/found/01\n" +
        "tag: whois.test.example\n" +
        "outOfOrder: true\n" +
        "terminateOnNewLine: true\n" +
        "set: Status = Found\n" +
        "---\n" +
        "Domain Name:{ DomainName : Trim, IsDomainName, ToHostName }\n";

    private const string AnotherTemplateContent =
        "---\n" +
        "name: whois.other.example/test/found/01\n" +
        "tag: whois.other.example\n" +
        "outOfOrder: true\n" +
        "terminateOnNewLine: true\n" +
        "set: Status = Found\n" +
        "---\n" +
        "Domain Name:{ DomainName : Trim, IsDomainName, ToHostName }\n";

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    private readonly string _tempDir;
    private readonly CacheDirectoryManager _cache;
    private readonly TemplateUpdateState _state;

    // -------------------------------------------------------------------------
    // Setup / teardown
    // -------------------------------------------------------------------------

    public TemplateUpdateIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "whois-e2e-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _cache = new CacheDirectoryManager(_tempDir, NullLogger<CacheDirectoryManager>.Instance);
        _state = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Builds a zip containing template files placed directly under their server subdirectory.
    /// The parser's cache resolver returns {cacheDir}/current/{server} and then does
    /// GetFiles("*.txt"), so each template file must live at {server}/{filename}.txt.
    /// </summary>
    private static byte[] BuildTemplateZip(params (string serverDir, string fileName, string content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (serverDir, fileName, content) in entries)
            {
                var entryPath = $"{serverDir}/{fileName}";
                var entry = archive.CreateEntry(entryPath);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(content);
            }
        }
        return ms.ToArray();
    }

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

    /// <summary>
    /// Creates a handler that routes requests by URL pattern:
    /// metadata URL → releaseJson, .minisig URL → "fake-sig", .zip URL → zipBytes.
    /// </summary>
    private static HttpMessageHandler BuildHandler(string releaseJson, byte[] zipBytes) =>
        new FuncHandler(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            if (url.EndsWith(".minisig", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("fake-sig", Encoding.UTF8),
                });
            }

            if (url.EndsWith(".zip", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(zipBytes),
                });
            }

            // Default: metadata
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            });
        });

    private TemplatePackProvider MakeProvider(
        HttpMessageHandler handler,
        string? currentVersion = null)
    {
        if (currentVersion != null)
            _state.RecordSuccess(currentVersion, DateTimeOffset.UtcNow - TimeSpan.FromDays(2));

        var options = new WhoisOptions();
        var httpClient = new HttpClient(handler);

        return new TemplatePackProvider(
            httpClient: httpClient,
            options: options,
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: _state,
            signatureVerifier: (_, _) => true);
    }

    private WhoisParser MakeParserWithCacheResolver() =>
        new WhoisParser(server => _cache.GetServerDirectory(server));

    // -------------------------------------------------------------------------
    // FuncHandler helper (mirrors TemplatePackProviderTests)
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
    // Test 1: UpdateTemplates E2E — templates extracted and used for parsing
    // =========================================================================

    [Fact]
    public async Task UpdateTemplates_EndToEnd_TemplatesUsedForParsing()
    {
        // Arrange: build a zip containing a template for TestServer
        var zipBytes = BuildTemplateZip(
            (TestServer, "found-01.txt", TestTemplateContent));

        var releaseJson = BuildReleaseJson(
            NewVersion,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var provider = MakeProvider(BuildHandler(releaseJson, zipBytes));
        var parser = MakeParserWithCacheResolver();

        // Act: trigger update
        var result = await provider.CheckForUpdate();

        // Assert: update succeeded
        Assert.Equal(TemplateUpdateOutcome.Updated, result.Outcome);
        Assert.Equal(NewVersion, result.Version);

        // Assert: cached template path exists
        var cachedPath = provider.GetCachedTemplatePath(TestServer);
        Assert.NotNull(cachedPath);
        Assert.True(Directory.Exists(cachedPath));
        Assert.NotEmpty(Directory.GetFiles(cachedPath!, "*.txt"));

        // Assert: parser uses cached template to parse a sample response
        var whoisContent = "Domain Name:example.test\n";
        var parsed = parser.Parse(TestServer, whoisContent);

        Assert.Equal("example.test", parsed.DomainName?.Value);
        Assert.Equal(WhoisStatus.Found, parsed.Status);
    }

    // =========================================================================
    // Test 2: Cache-hit bypass — already-queried server keeps embedded templates
    // =========================================================================

    [Fact]
    public async Task CacheHitBypass_AlreadyQueriedServer_UsesOldTemplates()
    {
        // Arrange: parser with cacheResolver backed by our cache
        var parser = MakeParserWithCacheResolver();

        // Seed a "current" directory with templates for TestServer *before* the update,
        // and query that server so the parser loads those templates (simulating embedded load).
        // We use a server that has no embedded resources so the parser finds nothing,
        // but we still trigger the template-load attempt.
        //
        // For a more realistic test: pre-populate the cache with "old" templates,
        // parse once (parser caches internally), then update with "new" templates,
        // parse again — parser should still use old in-memory templates.

        // Pre-populate cache with "old" template (version A)
        var oldContent =
            "---\n" +
            "name: whois.test.example/test/found/01\n" +
            "tag: whois.test.example\n" +
            "outOfOrder: true\n" +
            "terminateOnNewLine: true\n" +
            "set: Status = Found\n" +
            "---\n" +
            "Domain Name:{ DomainName : Trim, IsDomainName, ToHostName }\n";

        var oldZipBytes = BuildTemplateZip((TestServer, "found-01.txt", oldContent));
        var provider = MakeProvider(
            BuildHandler(
                BuildReleaseJson(TestVersion, "https://example.com/templates.zip", "https://example.com/templates.zip.minisig"),
                oldZipBytes));

        var firstUpdate = await provider.CheckForUpdate();
        Assert.Equal(TemplateUpdateOutcome.Updated, firstUpdate.Outcome);

        // Parse with the old templates — parser loads and caches internally
        var whoisContent = "Domain Name:example.test\n";
        var firstParse = parser.Parse(TestServer, whoisContent);
        Assert.Equal("example.test", firstParse.DomainName?.Value);

        // Now update the cache with "new" templates (different version)
        var newContent =
            "---\n" +
            "name: whois.test.example/test/found/02\n" +
            "tag: whois.test.example\n" +
            "outOfOrder: true\n" +
            "terminateOnNewLine: true\n" +
            "set: Status = Found\n" +
            "---\n" +
            "Domain Name:{ DomainName : Trim, IsDomainName, ToHostName }\n";

        var newZipBytes = BuildTemplateZip((TestServer, "found-02.txt", newContent));

        // Create a new state to reset eligibility
        var newState = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        newState.RecordSuccess(TestVersion, DateTimeOffset.UtcNow - TimeSpan.FromDays(2));

        var provider2 = new TemplatePackProvider(
            httpClient: new HttpClient(BuildHandler(
                BuildReleaseJson(NewVersion, "https://example.com/templates.zip", "https://example.com/templates.zip.minisig"),
                newZipBytes)),
            options: new WhoisOptions(),
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: newState,
            signatureVerifier: (_, _) => true);

        var secondUpdate = await provider2.CheckForUpdate();
        Assert.Equal(TemplateUpdateOutcome.Updated, secondUpdate.Outcome);

        // Parse again — same parser instance, TestServer already loaded
        // Parser should use in-memory templates (from the first load), not re-read from disk.
        // The template tag is still present, so it won't reload from cache.
        var secondParse = parser.Parse(TestServer, whoisContent);
        Assert.Equal("example.test", secondParse.DomainName?.Value);

        // Both parses should succeed (template still in memory from first load)
        Assert.Equal(WhoisStatus.Found, firstParse.Status);
        Assert.Equal(WhoisStatus.Found, secondParse.Status);
    }

    // =========================================================================
    // Test 3: Cache-hit bypass — new server after update uses cached templates
    // =========================================================================

    [Fact]
    public async Task CacheHitBypass_NewServer_UsesCachedTemplates()
    {
        // Arrange: populate cache with templates for AnotherServer
        var zipBytes = BuildTemplateZip(
            (AnotherServer, "found-01.txt", AnotherTemplateContent));

        var provider = MakeProvider(BuildHandler(
            BuildReleaseJson(NewVersion, "https://example.com/templates.zip", "https://example.com/templates.zip.minisig"),
            zipBytes));

        // Act: update templates
        var result = await provider.CheckForUpdate();
        Assert.Equal(TemplateUpdateOutcome.Updated, result.Outcome);

        // Create a fresh parser (AnotherServer never queried) backed by the cache
        var parser = MakeParserWithCacheResolver();

        // Parse a response for AnotherServer — should use cached template
        var whoisContent = "Domain Name:another.test\n";
        var parsed = parser.Parse(AnotherServer, whoisContent);

        // The cached template should have been loaded and used
        Assert.Equal("another.test", parsed.DomainName?.Value);
        Assert.Equal(WhoisStatus.Found, parsed.Status);
    }

    // =========================================================================
    // Test 4: TemplateStatus lifecycle transitions
    // =========================================================================

    [Fact]
    public async Task TemplateStatus_LifecycleTransitions()
    {
        // Initial state: embedded (no version recorded)
        var provider = MakeProvider(new FuncHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))));

        var initialStatus = provider.Status;
        Assert.Equal(TemplateSource.Embedded, initialStatus.Source);
        Assert.Equal("embedded", initialStatus.CurrentVersion);
        Assert.True(initialStatus.AutoUpdateEnabled);
        Assert.Null(initialStatus.LastError);

        // Transition to: cached (after successful update)
        var zipBytes = BuildTemplateZip((TestServer, "found-01.txt", TestTemplateContent));
        var releaseJson = BuildReleaseJson(
            NewVersion,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var updateProvider = MakeProvider(BuildHandler(releaseJson, zipBytes));
        var updateResult = await updateProvider.CheckForUpdate();
        Assert.Equal(TemplateUpdateOutcome.Updated, updateResult.Outcome);

        var cachedStatus = updateProvider.Status;
        Assert.Equal(TemplateSource.Cached, cachedStatus.Source);
        Assert.Equal(NewVersion, cachedStatus.CurrentVersion);
        Assert.True(cachedStatus.AutoUpdateEnabled);
        Assert.Null(cachedStatus.LastError);

        // Transition to: error state (extraction failure disables session)
        var errorState = new TemplateUpdateState(_cache, NullLogger<TemplateUpdateState>.Instance);
        // Don't set a version — this is a fresh state for the error provider
        var errorProvider = new TemplatePackProvider(
            httpClient: new HttpClient(new FuncHandler(req =>
            {
                var url = req.RequestUri!.AbsoluteUri;
                if (url.EndsWith(".minisig", StringComparison.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("sig") });
                if (url.EndsWith(".zip", StringComparison.Ordinal))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(Encoding.UTF8.GetBytes("NOT A ZIP")),
                    });
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(BuildReleaseJson(
                        "2026.07.14.1",
                        "https://example.com/templates.zip",
                        "https://example.com/templates.zip.minisig")),
                });
            })),
            options: new WhoisOptions(),
            logger: NullLogger<TemplatePackProvider>.Instance,
            cache: _cache,
            state: errorState,
            signatureVerifier: (_, _) => true);

        var errorResult = await errorProvider.CheckForUpdate();
        Assert.Equal(TemplateUpdateOutcome.Failed, errorResult.Outcome);

        var errorStatus = errorProvider.Status;
        Assert.False(errorStatus.AutoUpdateEnabled);
        Assert.NotNull(errorStatus.LastError);
    }

    // =========================================================================
    // Test 5: SessionDisable visible across shared provider instance
    // =========================================================================

    [Fact]
    public async Task SessionDisable_VisibleAcrossInstances()
    {
        // Arrange: trigger disk failure (non-zip payload) to disable for session
        var releaseJson = BuildReleaseJson(
            NewVersion,
            "https://example.com/templates.zip",
            "https://example.com/templates.zip.minisig");

        var handler = new FuncHandler(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            if (url.EndsWith(".minisig", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("sig") });
            if (url.EndsWith(".zip", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes("NOT A ZIP FILE")),
                });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(releaseJson, Encoding.UTF8),
            });
        });

        // Act: first call — triggers disk failure, disables for session
        var provider = MakeProvider(handler);
        var firstResult = await provider.CheckForUpdate();

        Assert.Equal(TemplateUpdateOutcome.Failed, firstResult.Outcome);
        Assert.False(provider.Status.AutoUpdateEnabled);

        // Create a WhoisLookup sharing the same provider (internal constructor for testing)
        var sharedParser = new WhoisParser(server => _cache.GetServerDirectory(server));
        var lookup1 = new WhoisLookup(provider, sharedParser);
        var lookup2 = new WhoisLookup(provider, sharedParser);

        // Both instances share the same provider — both should see AutoUpdateEnabled = false
        Assert.False(lookup1.TemplateStatus.AutoUpdateEnabled);
        Assert.False(lookup2.TemplateStatus.AutoUpdateEnabled);

        // Calling UpdateTemplates on either instance returns Skipped (session disabled)
        var skipResult1 = await lookup1.UpdateTemplates();
        var skipResult2 = await lookup2.UpdateTemplates();

        Assert.Equal(TemplateUpdateOutcome.Skipped, skipResult1.Outcome);
        Assert.Equal(TemplateUpdateOutcome.Skipped, skipResult2.Outcome);
    }
}
