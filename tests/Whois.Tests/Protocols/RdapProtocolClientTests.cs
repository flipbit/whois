using System.Net;
using NSubstitute;
using Whois.Protocols;
using Whois.Servers;
using Xunit;

namespace Whois;

public class RdapProtocolClientTests
{
    // ReadWithSizeLimit tests

    [Fact]
    public async Task ReadWithSizeLimit_EmptyResponse_ReturnsEmptyString()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty),
        };

        var result = await RdapProtocolClient.ReadWithSizeLimit(response, 2048, CancellationToken.None);

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public async Task ReadWithSizeLimit_ResponseAtLimit_ReturnsContent()
    {
        const int maxChars = 1000;
        var content = new string('x', maxChars);
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(content),
        };

        var result = await RdapProtocolClient.ReadWithSizeLimit(response, maxChars, CancellationToken.None);

        Assert.Equal(maxChars, result.Length);
        Assert.Equal(content, result);
    }

    [Fact]
    public async Task ReadWithSizeLimit_ResponseExceedsLimit_Throws()
    {
        const int maxChars = 1000;
        var content = new string('x', maxChars + 1);
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(content),
        };

        var ex = await Assert.ThrowsAsync<WhoisException>(
            () => RdapProtocolClient.ReadWithSizeLimit(response, maxChars, CancellationToken.None));

        Assert.Contains("exceeds maximum size", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadWithSizeLimit_WithContentLength_PreallocatesBuffer()
    {
        const int maxChars = 10000;
        var content = new string('x', 500);
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(content),
        };
        // Simulate Content-Length header
        response.Content.Headers.ContentLength = 500;

        var result = await RdapProtocolClient.ReadWithSizeLimit(response, maxChars, CancellationToken.None);

        Assert.Equal(content, result);
    }

    // ValidateUrl tests

    [Fact]
    public void ValidateUrl_HttpScheme_Throws()
    {
        var ex = Assert.Throws<WhoisException>(() => RdapProtocolClient.ValidateUrl("http://rdap.example.com/domain/foo.com"));
        Assert.Contains("HTTPS", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateUrl_NonDefaultPort_Throws()
    {
        var ex = Assert.Throws<WhoisException>(() => RdapProtocolClient.ValidateUrl("https://rdap.example.com:8443/domain/foo.com"));
        Assert.Contains("443", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateUrl_ValidHttpsUrl_DoesNotThrow()
    {
        // Should not throw
        RdapProtocolClient.ValidateUrl("https://rdap.example.com/domain/foo.com");
    }

    [Fact]
    public void ValidateUrl_ValidHttpsUrlWithExplicit443_DoesNotThrow()
    {
        // Port 443 explicitly is the same as default; should not throw.
        RdapProtocolClient.ValidateUrl("https://rdap.example.com:443/domain/foo.com");
    }

    // IsPrivateOrReservedAddress tests -- existing ranges

    [Theory]
    [InlineData("127.0.0.1")]       // loopback
    [InlineData("10.0.0.1")]        // RFC 1918 /8
    [InlineData("172.16.0.1")]      // RFC 1918 /12
    [InlineData("172.31.255.255")]  // RFC 1918 /12 upper bound
    [InlineData("192.168.1.1")]     // RFC 1918 /16
    [InlineData("169.254.1.1")]     // link-local
    public void IsPrivateOrReservedAddress_ExistingReservedRanges_ReturnsTrue(string address)
    {
        var ip = System.Net.IPAddress.Parse(address);
        Assert.True(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    // IsPrivateOrReservedAddress tests -- new ranges

    [Theory]
    [InlineData("0.0.0.1")]         // 0.0.0.0/8 this-network
    [InlineData("0.255.255.255")]   // 0.0.0.0/8 upper bound
    [InlineData("100.64.0.1")]      // CGNAT 100.64.0.0/10
    [InlineData("100.127.255.255")] // CGNAT upper bound
    public void IsPrivateOrReservedAddress_NewReservedRanges_ReturnsTrue(string address)
    {
        var ip = System.Net.IPAddress.Parse(address);
        Assert.True(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    // IsPrivateOrReservedAddress tests -- IPv6

    [Theory]
    [InlineData("::1")]             // IPv6 loopback
    [InlineData("fe80::1")]         // IPv6 link-local
    [InlineData("fc00::1")]         // IPv6 ULA fc00::/7
    [InlineData("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")] // IPv6 ULA fd upper bound
    public void IsPrivateOrReservedAddress_IPv6ReservedAddresses_ReturnsTrue(string address)
    {
        var ip = System.Net.IPAddress.Parse(address);
        Assert.True(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    [Fact]
    public void IsPrivateOrReservedAddress_IPv4MappedLoopback_ReturnsTrue()
    {
        // ::ffff:127.0.0.1 is IPv4-mapped IPv6 loopback -- must be caught.
        var ip = System.Net.IPAddress.Parse("::ffff:127.0.0.1");
        Assert.True(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    [Fact]
    public void IsPrivateOrReservedAddress_PublicIpv4_ReturnsFalse()
    {
        var ip = System.Net.IPAddress.Parse("8.8.8.8");
        Assert.False(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    [Fact]
    public void IsPrivateOrReservedAddress_PublicIpv6_ReturnsFalse()
    {
        // 2001:4860:4860::8888 is Google's public DNS over IPv6
        var ip = System.Net.IPAddress.Parse("2001:4860:4860::8888");
        Assert.False(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    // Boundary tests to avoid off-by-one errors in new ranges

    [Theory]
    [InlineData("100.63.255.255")]  // just below CGNAT range
    [InlineData("100.128.0.0")]     // just above CGNAT range
    public void IsPrivateOrReservedAddress_JustOutsideCgnat_ReturnsFalse(string address)
    {
        var ip = System.Net.IPAddress.Parse(address);
        Assert.False(RdapProtocolClient.IsPrivateOrReservedAddress(ip));
    }

    [Theory]
    [InlineData("example/com")]
    [InlineData("example?com")]
    [InlineData("example#com")]
    [InlineData("example @com")]
    [InlineData("example\\com")]
    public async Task Query_InvalidQueryChars_Throws(string query)
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var client = new RdapProtocolClient(new HttpClient(), bootstrap, new WhoisOptions());
        var request = new WhoisRequest(query);

        await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
    }

    [Fact]
    public async Task Query_NoRdapEndpoint_Throws()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("xyz", Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var client = new RdapProtocolClient(new HttpClient(), bootstrap, new WhoisOptions());
        var request = new WhoisRequest("example.xyz");

        var ex = await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
        Assert.Contains("No RDAP endpoint", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Protocol_ReturnsRdap()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var client = new RdapProtocolClient(new HttpClient(), bootstrap, new WhoisOptions());

        Assert.Equal(LookupProtocol.Rdap, client.Protocol);
    }

    [Fact]
    public async Task Query_Http404_ReturnsNotFound()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var handler = new FakeHttpHandler(HttpStatusCode.NotFound, string.Empty);
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("notfound.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal(RegistrationStatus.NotFound, response.Response.Status);
        Assert.Equal(LookupProtocol.Rdap, response.Protocol);
        Assert.Equal(404, response.Diagnostics.HttpStatusCode);
    }

    [Fact]
    public async Task Query_Http429_ReturnsThrottled()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var handler = new FakeHttpHandler((HttpStatusCode)429, string.Empty);
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("throttled.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal(RegistrationStatus.Throttled, response.Response.Status);
        Assert.Equal(LookupProtocol.Rdap, response.Protocol);
    }

    [Fact]
    public async Task Query_ValidResponse_ParsesDomainInfo()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));
        var handler = new FakeHttpHandler(HttpStatusCode.OK, json);
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("google.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal(LookupProtocol.Rdap, response.Protocol);
        Assert.Equal(RegistrationStatus.Found, response.Response.Status);
        Assert.NotNull(response.Response.Registrar);
        Assert.Equal(200, response.Diagnostics.HttpStatusCode);
        Assert.NotEmpty(response.RawContent);
    }

    [Fact]
    public async Task Query_ServerError_Throws()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var handler = new FakeHttpHandler(HttpStatusCode.InternalServerError, string.Empty);
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("example.com");

        await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
    }

    [Fact]
    public async Task Query_SlowResponseBody_TimesOut()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var handler = new SlowBodyStreamHandler();
        var httpClient = new HttpClient(handler);
        var options = new WhoisOptions { TimeoutSeconds = 1 };
        var client = new RdapProtocolClient(httpClient, bootstrap, options);
        var request = new WhoisRequest("slow.com");

        var ex = await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
        // The exception should contain "timed out" because the body read respects the timeout token
        Assert.Contains("timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Query_RedirectToPrivateIp_Throws()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        // First response is a 301 redirect to a private IP address.
        var handler = new RedirectHandler("https://192.168.1.1/domain/evil.com");
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("evil.com");

        var ex = await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
        Assert.Contains("private or reserved", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Query_RedirectChainExceedsLimit_Throws()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        // Always redirects -- creates an infinite chain that should be cut off at MaxRedirects + 1 (6 total requests).
        var handler = new CountingRedirectHandler("https://rdap.other.com/domain/loop.com");
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("loop.com");

        var ex = await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
        Assert.Contains("redirect", ex.Message, StringComparison.OrdinalIgnoreCase);
        // Verify exactly 6 requests were made: 1 original + 5 redirects before throwing
        Assert.Equal(6, handler.RequestCount);
    }

    [Fact]
    public async Task Query_ValidRedirectChain_Succeeds()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var json = File.ReadAllText(Path.Combine("..", "..", "..", "Samples", "rdap", "google-com.json"));

        // Redirect twice then return 200 OK.
        var handler = new RedirectThenOkHandler(redirectCount: 2, location: "https://rdap.other.com/domain/google.com", okBody: json);
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("google.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal(RegistrationStatus.Found, response.Response.Status);
    }

    [Fact]
    public async Task Query_HttpRequestException_WrapsInWhoisException()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var handler = new HttpRequestExceptionHandler("Connection reset by peer");
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("example.com");

        var ex = await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));

        Assert.Contains("RDAP request failed", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Connection reset by peer", ex.Message, StringComparison.Ordinal);
        Assert.IsType<HttpRequestException>(ex.InnerException);
        Assert.Equal("Connection reset by peer", ex.InnerException.Message);
    }

    /// <summary>
    /// Returns a 301 redirect for the first <c>redirectCount</c> calls, then a 200 OK with <c>okBody</c>.
    /// </summary>
    private sealed class RedirectThenOkHandler : HttpMessageHandler
    {
        private readonly int _redirectCount;
        private readonly string _location;
        private readonly string _okBody;
        private int _callCount;

        public RedirectThenOkHandler(int redirectCount, string location, string okBody)
        {
            _redirectCount = redirectCount;
            _location = location;
            _okBody = okBody;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _callCount++;
            if (_callCount <= _redirectCount)
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.Moved);
                redirect.Headers.Location = new Uri(_location);
                return Task.FromResult(redirect);
            }

            var ok = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_okBody),
            };
            return Task.FromResult(ok);
        }
    }

    /// <summary>
    /// Always returns a 301 redirect to <c>location</c>, used to trigger SSRF check or exceed the redirect limit.
    /// </summary>
    private sealed class RedirectHandler : HttpMessageHandler
    {
        private readonly string _location;

        public RedirectHandler(string location)
        {
            _location = location;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.Moved);
            response.Headers.Location = new Uri(_location);
            return Task.FromResult(response);
        }
    }

    /// <summary>
    /// Counts HTTP requests while always returning a 301 redirect to <c>location</c>.
    /// </summary>
    private sealed class CountingRedirectHandler : HttpMessageHandler
    {
        private readonly string _location;
        public int RequestCount { get; private set; }

        public CountingRedirectHandler(string location)
        {
            _location = location;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            var response = new HttpResponseMessage(HttpStatusCode.Moved);
            response.Headers.Location = new Uri(_location);
            return Task.FromResult(response);
        }
    }

    private sealed class FakeHttpHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _content;

        public FakeHttpHandler(HttpStatusCode statusCode, string content)
        {
            _statusCode = statusCode;
            _content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_content),
            };
            return Task.FromResult(response);
        }
    }

    private sealed class SlowBodyStreamHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new SlowStream()),
            };
            return Task.FromResult(response);
        }
    }

    private sealed class SlowStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Synchronous read - just block for a long time
            System.Threading.Thread.Sleep(5000);
            return 0;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // Asynchronous read with cancellation support
            // Delay for 5 seconds, which should exceed the 1 second timeout
            try
            {
                await Task.Delay(5000, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Re-throw to let the caller handle the cancellation
                throw;
            }
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    /// <summary>
    /// Throws HttpRequestException to simulate network failures.
    /// </summary>
    private sealed class HttpRequestExceptionHandler : HttpMessageHandler
    {
        private readonly string _message;

        public HttpRequestExceptionHandler(string message)
        {
            _message = message;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException(_message);
        }
    }
}
