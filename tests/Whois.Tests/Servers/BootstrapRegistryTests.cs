using System.Net;
using System.Text;
using Xunit;

namespace Whois.Servers;

public class BootstrapRegistryTests
{
    // Minimal valid IANA RDAP bootstrap JSON for testing
    private const string ValidRdapBootstrapJson = """
        {
          "version": "1.0",
          "services": [
            [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
            [["org"], ["https://rdap.org.example/"]],
            [["httponly"], ["http://insecure.example.com/"]]
          ]
        }
        """;

    // --- RDAP (HTTP-fetched) ---

    [Fact]
    public async Task GetRdapBaseUrl_KnownTld_FetchesAndReturnsUrl()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var url = await registry.GetRdapBaseUrl("com", CancellationToken.None);

        Assert.Equal("https://rdap.verisign.com/com/v1/", url);
    }

    [Fact]
    public async Task GetRdapBaseUrl_UnknownTld_ReturnsNull()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var url = await registry.GetRdapBaseUrl("zzz-nonexistent", CancellationToken.None);

        Assert.Null(url);
    }

    [Fact]
    public async Task GetRdapBaseUrl_CaseInsensitive()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var lower = await registry.GetRdapBaseUrl("com", CancellationToken.None);
        var upper = await registry.GetRdapBaseUrl("COM", CancellationToken.None);

        Assert.Equal(lower, upper);
    }

    [Fact]
    public async Task GetRdapBaseUrl_CachesAfterFirstFetch()
    {
        var handler = new CountingHandler(HttpStatusCode.OK, ValidRdapBootstrapJson);
        var registry = CreateRegistry(handler);

        await registry.GetRdapBaseUrl("com", CancellationToken.None);
        await registry.GetRdapBaseUrl("org", CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task GetRdapBaseUrl_HttpError_ThrowsWhoisException()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.InternalServerError, "error");

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => registry.GetRdapBaseUrl("com", CancellationToken.None));
        Assert.Contains("500", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetRdapBaseUrl_MalformedJson_ThrowsWhoisException()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, "not json");

        await Assert.ThrowsAsync<WhoisException>(
            () => registry.GetRdapBaseUrl("com", CancellationToken.None));
    }

    [Fact]
    public async Task GetRdapBaseUrl_ResponseTooLarge_ThrowsWhoisException()
    {
        var largeJson = new string('x', 1_100_000); // > 1 MB
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, largeJson);

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => registry.GetRdapBaseUrl("com", CancellationToken.None));
        Assert.Contains("size", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetRdapBaseUrl_FailedFetchLeavesNullCache_NextCallRetries()
    {
        var handler = new SequenceHandler(
            (HttpStatusCode.InternalServerError, "error"),
            (HttpStatusCode.OK, ValidRdapBootstrapJson));
        var registry = CreateRegistry(handler);

        // First call fails
        await Assert.ThrowsAsync<WhoisException>(
            () => registry.GetRdapBaseUrl("com", CancellationToken.None));

        // Second call retries and succeeds
        var url = await registry.GetRdapBaseUrl("com", CancellationToken.None);
        Assert.NotNull(url);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task Refresh_ClearsRdapCache_NextCallRefetches()
    {
        var handler = new CountingHandler(HttpStatusCode.OK, ValidRdapBootstrapJson);
        var registry = CreateRegistry(handler);

        await registry.GetRdapBaseUrl("com", CancellationToken.None);
        Assert.Equal(1, handler.CallCount);

        await registry.Refresh(CancellationToken.None);

        await registry.GetRdapBaseUrl("com", CancellationToken.None);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task GetRdapBaseUrl_ConcurrentCalls_OnlyOneFetch()
    {
        var handler = new SlowHandler(HttpStatusCode.OK, ValidRdapBootstrapJson, delay: TimeSpan.FromMilliseconds(100));
        var registry = CreateRegistry(handler);

        var tasks = Enumerable.Range(0, 10)
            .Select(_ => registry.GetRdapBaseUrl("com", CancellationToken.None))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, handler.CallCount);
        Assert.All(results, url => Assert.NotNull(url));
    }

    // --- WHOIS (embedded, unchanged) ---

    [Fact]
    public async Task GetWhoisServer_KnownTld_ReturnsHostname()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var server = await registry.GetWhoisServer("com", CancellationToken.None);

        Assert.NotNull(server);
        Assert.Contains("whois", server, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetWhoisServer_UnknownTld_ReturnsNull()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var server = await registry.GetWhoisServer("zzz-nonexistent", CancellationToken.None);

        Assert.Null(server);
    }

    [Fact]
    public async Task GetWhoisServer_CaseInsensitive()
    {
        var registry = CreateRegistryWithRdapResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var lower = await registry.GetWhoisServer("com", CancellationToken.None);
        var upper = await registry.GetWhoisServer("COM", CancellationToken.None);

        Assert.Equal(lower, upper);
    }

    [Fact]
    public async Task GetWhoisServer_DoesNotRequireHttpFetch()
    {
        // WHOIS uses embedded data -- no HTTP call needed.
        // Use a handler that throws to prove no HTTP call is made.
        var handler = new ThrowingHandler();
        var registry = CreateRegistry(handler);

        var server = await registry.GetWhoisServer("com", CancellationToken.None);

        Assert.NotNull(server);
    }

    // --- ParseBootstrapJson (static parser, no mocks needed) ---

    [Fact]
    public void ParseBootstrapJson_OnlyAcceptsHttps()
    {
        const string json = """
            {
              "services": [
                [["example"], ["http://insecure.example.com/", "https://secure.example.com/"]],
                [["httponly"], ["http://httponly.example.com/"]]
              ]
            }
            """;

        var result = BootstrapRegistry.ParseBootstrapJson(json);

        Assert.True(result.ContainsKey("example"));
        Assert.Equal("https://secure.example.com/", result["example"]);
        Assert.False(result.ContainsKey("httponly"));
    }

    // --- Test helpers ---

    private static BootstrapRegistry CreateRegistryWithRdapResponse(HttpStatusCode statusCode, string body)
    {
        return CreateRegistry(new CountingHandler(statusCode, body));
    }

    private static BootstrapRegistry CreateRegistry(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler);
        return new BootstrapRegistry(httpClient, new WhoisOptions());
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;
        private int _callCount;

        public int CallCount => _callCount;

        public CountingHandler(HttpStatusCode statusCode, string body)
        {
            _statusCode = statusCode;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _callCount);
            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }

    private sealed class SequenceHandler : HttpMessageHandler
    {
        private readonly (HttpStatusCode Status, string Body)[] _responses;
        private int _callCount;

        public int CallCount => _callCount;

        public SequenceHandler(params (HttpStatusCode, string)[] responses)
        {
            _responses = responses;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var index = Interlocked.Increment(ref _callCount) - 1;
            var (status, body) = _responses[Math.Min(index, _responses.Length - 1)];
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }

    private sealed class SlowHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;
        private readonly TimeSpan _delay;
        private int _callCount;

        public int CallCount => _callCount;

        public SlowHandler(HttpStatusCode statusCode, string body, TimeSpan delay)
        {
            _statusCode = statusCode;
            _body = body;
            _delay = delay;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _callCount);
            await Task.Delay(_delay, ct).ConfigureAwait(false);
            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
            return response;
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            throw new InvalidOperationException("No HTTP call should be made for WHOIS lookups");
        }
    }
}
