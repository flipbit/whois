using Xunit;
using Whois.Servers;

namespace Whois;

public class IanaServerLookupTest
{
    private readonly IanaServerLookup lookup;

    public IanaServerLookupTest()
    {
        lookup = new IanaServerLookup();
    }

    [Fact]
    public async Task TestLookupCom()
    {
        var result = await lookup.Lookup(new WhoisRequest("com"));

        Assert.Equal("whois.verisign-grs.com", result.Registrar.WhoisServer.ToString());
    }

    [Fact]
    public async Task TestLookupComBr()
    {
        var result = await lookup.Lookup(new WhoisRequest("br"));

        Assert.Equal("whois.registro.br", result.Registrar.WhoisServer.ToString());
    }
}
