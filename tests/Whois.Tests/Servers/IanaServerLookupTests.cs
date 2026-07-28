using System.Text;
using NSubstitute;
using Whois.Net;
using Xunit;

namespace Whois.Servers;

public class IanaServerLookupTests
{
    // Sample IANA response for .com TLD (simplified from real response)
    private const string IanaResponseCom = """
        % IANA WHOIS server
        % for more information on IANA, visit http://www.iana.org

        domain:       COM

        organisation: VeriSign Global Registry Services
        address:      12061 Bluemont Way
        address:      Reston VA 20190
        address:      United States of America (the)

        contact:      administrative
        name:         Registry Customer Service
        organisation: VeriSign Global Registry Services

        contact:      technical
        name:         Registry Customer Service
        organisation: VeriSign Global Registry Services

        nserver:      A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30
        nserver:      B.GTLD-SERVERS.NET 192.33.14.30 2001:503:231d:0:0:0:2:30

        whois:        whois.verisign-grs.com

        status:       ACTIVE
        remarks:      Registration information: http://www.verisigninc.com

        created:      1985-01-01
        changed:      2023-12-07
        source:       IANA
        """;

    // Sample IANA response for a TLD with no WHOIS server
    private const string IanaResponseNoWhois = """
        % IANA WHOIS server

        domain:       EXAMPLE

        organisation: IANA

        nserver:      NS1.EXAMPLE.COM

        status:       ACTIVE

        created:      2000-01-01
        source:       IANA
        """;

    [Fact]
    public async Task GetWhoisServer_KnownTld_ReturnsHostname()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "com", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(IanaResponseCom);

        var lookup = new IanaServerLookup(tcpReader, new WhoisOptions());

        var server = await lookup.GetWhoisServer("com", CancellationToken.None);

        Assert.Equal("whois.verisign-grs.com", server);
    }

    [Fact]
    public async Task GetWhoisServer_NoWhoisField_ReturnsNull()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "example", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(IanaResponseNoWhois);

        var lookup = new IanaServerLookup(tcpReader, new WhoisOptions());

        var server = await lookup.GetWhoisServer("example", CancellationToken.None);

        Assert.Null(server);
    }

    [Fact]
    public async Task GetWhoisServer_CachesResult()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "com", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(IanaResponseCom);

        var lookup = new IanaServerLookup(tcpReader, new WhoisOptions());

        await lookup.GetWhoisServer("com", CancellationToken.None);
        await lookup.GetWhoisServer("com", CancellationToken.None);

        await tcpReader.Received(1).Read("whois.iana.org", 43, "com",
            Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetWhoisServer_CaseInsensitive()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "com", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(IanaResponseCom);

        var lookup = new IanaServerLookup(tcpReader, new WhoisOptions());

        var lower = await lookup.GetWhoisServer("com", CancellationToken.None);
        var upper = await lookup.GetWhoisServer("COM", CancellationToken.None);

        Assert.Equal(lower, upper);
        // Only one TCP call -- "COM" was normalized to "com" and found in cache
        await tcpReader.Received(1).Read("whois.iana.org", 43, "com",
            Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetWhoisServer_TtlExpired_Requeried()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "com", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(IanaResponseCom);

        var options = new WhoisOptions { TldServerCacheDuration = TimeSpan.FromMilliseconds(50) };
        var lookup = new IanaServerLookup(tcpReader, options);

        await lookup.GetWhoisServer("com", CancellationToken.None);
        await Task.Delay(100);
        await lookup.GetWhoisServer("com", CancellationToken.None);

        await tcpReader.Received(2).Read("whois.iana.org", 43, "com",
            Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ClearCache_ForcesRequery()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "com", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(IanaResponseCom);

        var lookup = new IanaServerLookup(tcpReader, new WhoisOptions());

        await lookup.GetWhoisServer("com", CancellationToken.None);
        lookup.ClearCache();
        await lookup.GetWhoisServer("com", CancellationToken.None);

        await tcpReader.Received(2).Read("whois.iana.org", 43, "com",
            Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetWhoisServer_EmptyResponse_ReturnsNull()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        tcpReader.Read("whois.iana.org", 43, "zzz", Arg.Any<Encoding>(),
                Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns("");

        var lookup = new IanaServerLookup(tcpReader, new WhoisOptions());

        var server = await lookup.GetWhoisServer("zzz", CancellationToken.None);

        Assert.Null(server);
    }
}
