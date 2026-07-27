using System.Net;
using System.Text;
using Whois.Refresh.Domain;
using Xunit;

namespace Whois.Refresh.Tests.Domain;

public class RdapRefreshEngineTests
{
    // Minimal valid RDAP response for a found domain
    private const string ValidRdapResponse = """
        {
          "ldhName": "example.com",
          "status": ["active"],
          "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}
          ]
        }
        """;

    [Fact]
    public async Task RunAsync_SuccessfulQuery_RecordsFieldsExtracted()
    {
        using var handler = new FakeHandler(HttpStatusCode.OK, ValidRdapResponse);
        var engine = CreateEngine(handler);
        var registry = CreateRegistry("rdap.example.com", "com",
            rdapBaseUrl: "https://rdap.example.com/",
            domains: new Dictionary<string, IList<string>>(StringComparer.Ordinal) { ["found"] = ["example.com"] });

        var results = await engine.RunAsync(registry, CreateOptions(), CancellationToken.None);

        var domainResult = results.Results["rdap.example.com"]["com"]["found"]["example.com"];
        Assert.Null(domainResult.Error);
        Assert.Contains("DomainName", domainResult.ExtractedFields);
    }

    [Fact]
    public async Task RunAsync_HttpError_RecordsError()
    {
        using var handler = new FakeHandler(HttpStatusCode.InternalServerError, "error");
        var engine = CreateEngine(handler);
        var registry = CreateRegistry("rdap.example.com", "com",
            rdapBaseUrl: "https://rdap.example.com/",
            domains: new Dictionary<string, IList<string>>(StringComparer.Ordinal) { ["found"] = ["example.com"] });

        var results = await engine.RunAsync(registry, CreateOptions(), CancellationToken.None);

        var domainResult = results.Results["rdap.example.com"]["com"]["found"]["example.com"];
        Assert.NotNull(domainResult.Error);
    }

    [Fact]
    public async Task RunAsync_NotFound_RecordsNotFoundStatus()
    {
        using var handler = new FakeHandler(HttpStatusCode.NotFound, "");
        var engine = CreateEngine(handler);
        var registry = CreateRegistry("rdap.example.com", "com",
            rdapBaseUrl: "https://rdap.example.com/",
            domains: new Dictionary<string, IList<string>>(StringComparer.Ordinal) { ["not-found"] = ["nonexistent.com"] });

        var results = await engine.RunAsync(registry, CreateOptions(), CancellationToken.None);

        var domainResult = results.Results["rdap.example.com"]["com"]["not-found"]["nonexistent.com"];
        Assert.Null(domainResult.Error);
        Assert.Equal("not-found", domainResult.ActualStatus ?? "not-found");
    }

    [Fact]
    public async Task RunAsync_SkipsStaticEntries()
    {
        using var handler = new FakeHandler(HttpStatusCode.OK, ValidRdapResponse);
        var engine = CreateEngine(handler);
        var servers = new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            ["rdap.static.com"] = new("com", IsStatic: true, null,
                new Dictionary<string, IList<string>>(StringComparer.Ordinal) { ["found"] = ["static.com"] },
                RdapBaseUrl: "https://rdap.static.com/"),
        };
        var registry = new DomainRegistryData(servers);

        var results = await engine.RunAsync(registry, CreateOptions(), CancellationToken.None);

        Assert.Empty(results.Results);
    }

    [Fact]
    public async Task RunAsync_MissingRdapBaseUrl_RecordsError()
    {
        using var handler = new FakeHandler(HttpStatusCode.OK, ValidRdapResponse);
        var engine = CreateEngine(handler);
        var registry = CreateRegistry("rdap.example.com", "com",
            rdapBaseUrl: null,
            domains: new Dictionary<string, IList<string>>(StringComparer.Ordinal) { ["found"] = ["example.com"] });

        var results = await engine.RunAsync(registry, CreateOptions(), CancellationToken.None);

        var domainResult = results.Results["rdap.example.com"]["com"]["found"]["example.com"];
        Assert.NotNull(domainResult.Error);
        Assert.Equal(QueryErrorType.Unknown, domainResult.Error.Type);
    }

    // --- Helpers ---

    private static RdapRefreshEngine CreateEngine(HttpMessageHandler handler)
    {
#pragma warning disable CA2000 // HttpClient lifetime managed by test scope
        return new RdapRefreshEngine(new HttpClient(handler));
#pragma warning restore CA2000
    }

    private static RdapRefreshEngineOptions CreateOptions()
    {
        return new RdapRefreshEngineOptions(
            DelayBetweenQueries: TimeSpan.Zero,
            QueryTimeoutSeconds: 10);
    }

    private static DomainRegistryData CreateRegistry(
        string serverName, string tld, string? rdapBaseUrl,
        Dictionary<string, IList<string>> domains)
    {
        var servers = new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            [serverName] = new(tld, IsStatic: false, null, domains, rdapBaseUrl),
        };
        return new DomainRegistryData(servers);
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _body;

        public FakeHandler(HttpStatusCode statusCode, string body)
        {
            _statusCode = statusCode;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            });
        }
    }
}
