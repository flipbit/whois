using Whois.Net;
using Whois.Servers;
using Xunit;

namespace Whois;

public class IanaServerLookupTest
{
    [Fact]
    public async Task GetWhoisServer_Com_ReturnsVerisign()
    {
        var lookup = new IanaServerLookup(new TcpReader(), new WhoisOptions());

        var server = await lookup.GetWhoisServer("com", CancellationToken.None);

        Assert.Equal("whois.verisign-grs.com", server);
    }

    [Fact]
    public async Task GetWhoisServer_Br_ReturnsRegistroBr()
    {
        var lookup = new IanaServerLookup(new TcpReader(), new WhoisOptions());

        var server = await lookup.GetWhoisServer("br", CancellationToken.None);

        Assert.Equal("whois.registro.br", server);
    }
}
