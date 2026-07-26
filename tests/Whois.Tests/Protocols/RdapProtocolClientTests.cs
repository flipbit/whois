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
}
