using System.Net;
using NSubstitute;
using Whois.Protocols;
using Whois.Servers;
using Xunit;

namespace Whois;

public class RdapProtocolClientTests
{
    [Theory]
    [InlineData("example/com")]
    [InlineData("example?com")]
    [InlineData("example#com")]
    [InlineData("example @com")]
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

        // Always redirects -- creates an infinite chain that should be cut off at 5.
        var handler = new RedirectHandler("https://rdap.other.com/domain/loop.com");
        var httpClient = new HttpClient(handler);
        var client = new RdapProtocolClient(httpClient, bootstrap, new WhoisOptions());
        var request = new WhoisRequest("loop.com");

        var ex = await Assert.ThrowsAsync<WhoisException>(() => client.Query(request, CancellationToken.None));
        Assert.Contains("redirect", ex.Message, StringComparison.OrdinalIgnoreCase);
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
}
