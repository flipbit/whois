using NSubstitute;
using Whois.Protocols;
using Whois.Servers;
using Xunit;

namespace Whois;

public class WhoisLookupTest
{
    [Fact]
    public async Task Lookup_AutoProtocol_UsesRdapWhenAvailable()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.verisign.com/com/v1/");

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);
        rdapClient.Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ProtocolResponse
            {
                RawContent = "{}",
                Protocol = LookupProtocol.Rdap,
                Response = new DomainInfo
                {
                    DomainName = new HostName("google.com"),
                    Status = RegistrationStatus.Found,
                },
                Diagnostics = new LookupDiagnostics(),
            });

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            bootstrap,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup("google.com");

        Assert.Equal(LookupProtocol.Rdap, result.Protocol);
        Assert.Equal("google.com", result.Response.DomainName!.ToString());
    }

    [Fact]
    public async Task Lookup_AutoProtocol_FallsBackToWhoisWhenNoRdap()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("uk", Arg.Any<CancellationToken>())
            .Returns((string?)null);
        bootstrap.GetWhoisServer("uk", Arg.Any<CancellationToken>())
            .Returns("whois.nic.uk");

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);
        whoisClient.Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ProtocolResponse
            {
                RawContent = "Domain Name: example.uk",
                Protocol = LookupProtocol.Whois,
                Response = new DomainInfo
                {
                    DomainName = new HostName("example.uk"),
                    Status = RegistrationStatus.Found,
                },
                Diagnostics = new LookupDiagnostics { ServerUrl = "whois.nic.uk" },
            });

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            bootstrap,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup("example.uk");

        Assert.Equal(LookupProtocol.Whois, result.Protocol);
    }

    [Fact]
    public async Task Lookup_ForceWhois_UsesWhoisEvenWhenRdapAvailable()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.verisign.com/com/v1/");
        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.verisign-grs.com");

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);
        whoisClient.Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ProtocolResponse
            {
                RawContent = "Domain Name: GOOGLE.COM",
                Protocol = LookupProtocol.Whois,
                Response = new DomainInfo
                {
                    DomainName = new HostName("google.com"),
                    Status = RegistrationStatus.Found,
                },
                Diagnostics = new LookupDiagnostics(),
            });

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);

        var request = new WhoisRequest("google.com") { PreferredProtocol = ProtocolPreference.Whois };

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            bootstrap,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Whois, result.Protocol);
        await rdapClient.DidNotReceive().Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Lookup_ForceRdap_ThrowsWhenNotAvailable()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        bootstrap.GetRdapBaseUrl("uk", Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            bootstrap,
            []);

        var request = new WhoisRequest("example.uk") { PreferredProtocol = ProtocolPreference.Rdap };

        await Assert.ThrowsAsync<WhoisException>(() => lookup.Lookup(request));
    }

    [Fact]
    public async Task Lookup_EmptyQuery_ThrowsArgumentNullException()
    {
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var lookup = new WhoisLookup(new WhoisOptions(), bootstrap, []);

        await Assert.ThrowsAsync<ArgumentNullException>(() => lookup.Lookup(string.Empty));
    }
}
