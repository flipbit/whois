using Xunit;
using Whois.Net;
using Whois.Servers;

namespace Whois;

public class BootstrapRegistryTest : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly RdapRegistryCache _rdapRegistry;
    private readonly IanaServerLookup _ianaLookup;

    public BootstrapRegistryTest()
    {
        _httpClient = new HttpClient();
        _rdapRegistry = new RdapRegistryCache(_httpClient, new WhoisOptions());
        _ianaLookup = new IanaServerLookup(new TcpReader(), new WhoisOptions());
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [Fact]
    public async Task TestLookupCom()
    {
        var result = await _ianaLookup.GetWhoisServer("com", CancellationToken.None);

        Assert.Equal("whois.verisign-grs.com", result);
    }

    [Fact]
    public async Task TestLookupBr()
    {
        var result = await _ianaLookup.GetWhoisServer("br", CancellationToken.None);

        Assert.Equal("whois.registro.br", result);
    }

    [Fact]
    public async Task TestRdapLookupCom()
    {
        var result = await _rdapRegistry.GetBaseUrl("com", CancellationToken.None);

        Assert.NotNull(result);
        Assert.StartsWith("https://", result);
    }
}
