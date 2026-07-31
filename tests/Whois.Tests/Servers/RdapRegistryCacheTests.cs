using System.Net;
using System.Text;
using Xunit;

namespace Whois.Servers;

public class RdapRegistryCacheTests
{
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

    [Fact]
    public async Task GetBaseUrl_KnownTld_FetchesAndReturnsUrl()
    {
        var cache = CreateCacheWithResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var url = await cache.GetBaseUrl("com", CancellationToken.None);

        Assert.Equal("https://rdap.verisign.com/com/v1/", url);
    }

    [Fact]
    public async Task GetBaseUrl_UnknownTld_ReturnsNull()
    {
        var cache = CreateCacheWithResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var url = await cache.GetBaseUrl("zzz-nonexistent", CancellationToken.None);

        Assert.Null(url);
    }

    [Fact]
    public async Task GetBaseUrl_CaseInsensitive()
    {
        var cache = CreateCacheWithResponse(HttpStatusCode.OK, ValidRdapBootstrapJson);

        var lower = await cache.GetBaseUrl("com", CancellationToken.None);
        var upper = await cache.GetBaseUrl("COM", CancellationToken.None);

        Assert.Equal(lower, upper);
    }

    [Fact]
    public async Task GetBaseUrl_CachesAfterFirstFetch()
    {
        var handler = new CountingHandler(HttpStatusCode.OK, ValidRdapBootstrapJson);
        var cache = CreateCache(handler);

        await cache.GetBaseUrl("com", CancellationToken.None);
        await cache.GetBaseUrl("org", CancellationToken.None);

        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task GetBaseUrl_HttpError_ThrowsWhoisException()
    {
        var cache = CreateCacheWithResponse(HttpStatusCode.InternalServerError, "error");

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => cache.GetBaseUrl("com", CancellationToken.None));
        Assert.Contains("500", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetBaseUrl_MalformedJson_ThrowsWhoisException()
    {
        var cache = CreateCacheWithResponse(HttpStatusCode.OK, "not json");

        await Assert.ThrowsAsync<WhoisException>(
            () => cache.GetBaseUrl("com", CancellationToken.None));
    }

    [Fact]
    public async Task GetBaseUrl_ResponseTooLarge_ThrowsWhoisException()
    {
        var largeJson = new string('x', 1_100_000);
        var cache = CreateCacheWithResponse(HttpStatusCode.OK, largeJson);

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => cache.GetBaseUrl("com", CancellationToken.None));
        Assert.Contains("size", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetBaseUrl_FailedFetchRetries()
    {
        var handler = new SequenceHandler(
            (HttpStatusCode.InternalServerError, "error"),
            (HttpStatusCode.OK, ValidRdapBootstrapJson));
        var cache = CreateCache(handler);

        await Assert.ThrowsAsync<WhoisException>(
            () => cache.GetBaseUrl("com", CancellationToken.None));

        var url = await cache.GetBaseUrl("com", CancellationToken.None);
        Assert.NotNull(url);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task ClearCache_NextCallRefetches()
    {
        var handler = new CountingHandler(HttpStatusCode.OK, ValidRdapBootstrapJson);
        var cache = CreateCache(handler);

        await cache.GetBaseUrl("com", CancellationToken.None);
        Assert.Equal(1, handler.CallCount);

        cache.ClearCache();

        await cache.GetBaseUrl("com", CancellationToken.None);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task GetBaseUrl_ConcurrentCalls_OnlyOneFetch()
    {
        var handler = new SlowHandler(HttpStatusCode.OK, ValidRdapBootstrapJson, delay: TimeSpan.FromMilliseconds(100));
        var cache = CreateCache(handler);

        var tasks = Enumerable.Range(0, 10)
            .Select(_ => cache.GetBaseUrl("com", CancellationToken.None))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, handler.CallCount);
        Assert.All(results, url => Assert.NotNull(url));
    }

    [Fact]
    public async Task GetBaseUrl_TtlExpired_Refetches()
    {
        var handler = new CountingHandler(HttpStatusCode.OK, ValidRdapBootstrapJson);
        var options = new WhoisOptions { TldServerCacheDuration = TimeSpan.FromMilliseconds(50) };
        var cache = new RdapRegistryCache(new HttpClient(handler), options);

        await cache.GetBaseUrl("com", CancellationToken.None);
        Assert.Equal(1, handler.CallCount);

        await Task.Delay(100);

        await cache.GetBaseUrl("com", CancellationToken.None);
        Assert.Equal(2, handler.CallCount);
    }

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

        var result = RdapRegistryCache.ParseBootstrapJson(json);

        Assert.True(result.ContainsKey("example"));
        Assert.Equal("https://secure.example.com/", result["example"]);
        Assert.False(result.ContainsKey("httponly"));
    }

    [Fact]
    public async Task GetBaseUrl_Timeout_ThrowsWhoisException()
    {
        var handler = new TimeoutHandler();
        var options = new WhoisOptions { TimeoutSeconds = 1 };
        var cache = new RdapRegistryCache(new HttpClient(handler), options);

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => cache.GetBaseUrl("com", CancellationToken.None));
        Assert.Contains("timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetBaseUrl_HttpRequestException_ThrowsWhoisException()
    {
        var handler = new ThrowingHandler();
        var cache = new RdapRegistryCache(new HttpClient(handler), new WhoisOptions());

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => cache.GetBaseUrl("com", CancellationToken.None));
        Assert.Contains("fetch failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // --- Test helpers ---

    private static RdapRegistryCache CreateCacheWithResponse(HttpStatusCode statusCode, string body)
    {
        return CreateCache(new CountingHandler(statusCode, body));
    }

    private static RdapRegistryCache CreateCache(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler);
        return new RdapRegistryCache(httpClient, new WhoisOptions());
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

    private sealed class TimeoutHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            throw new HttpRequestException("Connection refused");
        }
    }
}
