using Xunit;
using Whois.Servers;

namespace Whois;

public class RdapRegistryCacheTest : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly RdapRegistryCache _cache;

    public RdapRegistryCacheTest()
    {
        _httpClient = new HttpClient();
        _cache = new RdapRegistryCache(_httpClient, new WhoisOptions());
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [Fact]
    public async Task GetBaseUrl_Com_ReturnsHttpsUrl()
    {
        var result = await _cache.GetBaseUrl("com", CancellationToken.None);

        Assert.NotNull(result);
        Assert.StartsWith("https://", result);
    }
}
