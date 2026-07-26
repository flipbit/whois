using Xunit;
using Whois.Servers;

namespace Whois;

public class BootstrapRegistryTest
{
    private readonly BootstrapRegistry registry;

    public BootstrapRegistryTest()
    {
        registry = new BootstrapRegistry();
    }

    [Fact]
    public async Task TestLookupCom()
    {
        var result = await registry.GetWhoisServer("com", CancellationToken.None);

        Assert.Equal("whois.verisign-grs.com", result);
    }

    [Fact]
    public async Task TestLookupBr()
    {
        var result = await registry.GetWhoisServer("br", CancellationToken.None);

        Assert.Equal("whois.registro.br", result);
    }

    [Fact]
    public async Task TestRdapLookupCom()
    {
        var result = await registry.GetRdapBaseUrl("com", CancellationToken.None);

        Assert.NotNull(result);
        Assert.StartsWith("https://", result);
    }
}
