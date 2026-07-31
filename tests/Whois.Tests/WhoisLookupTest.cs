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
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("com", Arg.Any<CancellationToken>())
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
            rdapRegistry,
            ianaLookup,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup("google.com");

        Assert.Equal(LookupProtocol.Rdap, result.Protocol);
        Assert.Equal("google.com", result.Response.DomainName!.ToString());
    }

    [Fact]
    public async Task Lookup_AutoProtocol_FallsBackToWhoisWhenNoRdap()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("uk", Arg.Any<CancellationToken>())
            .Returns((string?)null);
        ianaLookup.GetWhoisServer("uk", Arg.Any<CancellationToken>())
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
            rdapRegistry,
            ianaLookup,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup("example.uk");

        Assert.Equal(LookupProtocol.Whois, result.Protocol);
    }

    [Fact]
    public async Task Lookup_ForceWhois_UsesWhoisEvenWhenRdapAvailable()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.verisign.com/com/v1/");
        ianaLookup.GetWhoisServer("com", Arg.Any<CancellationToken>())
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
            rdapRegistry,
            ianaLookup,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Whois, result.Protocol);
        await rdapClient.DidNotReceive().Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Lookup_ForceRdap_ThrowsWhenNotAvailable()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("uk", Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            rdapRegistry,
            ianaLookup,
            [whoisClient, rdapClient]);

        var request = new WhoisRequest("example.uk") { PreferredProtocol = ProtocolPreference.Rdap };

        await Assert.ThrowsAsync<WhoisException>(() => lookup.Lookup(request));
    }

    [Fact]
    public async Task Lookup_GlobalPreferredProtocol_UsedWhenRequestProtocolIsNull()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.verisign.com/com/v1/");
        ianaLookup.GetWhoisServer("com", Arg.Any<CancellationToken>())
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

        // Global option forces WHOIS; request leaves PreferredProtocol null (inherits global).
        var options = new WhoisOptions { PreferredProtocol = ProtocolPreference.Whois };
        var request = new WhoisRequest("google.com"); // PreferredProtocol is null

        var lookup = new WhoisLookup(options, rdapRegistry, ianaLookup, [whoisClient, rdapClient]);

        var result = await lookup.Lookup(request);

        Assert.Equal(LookupProtocol.Whois, result.Protocol);
        await rdapClient.DidNotReceive().Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Lookup_LeadingDot_NormalizesToDomainWithoutDot()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("com", Arg.Any<CancellationToken>())
            .Returns("https://rdap.verisign.com/com/v1/");

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);
        rdapClient.Query(Arg.Any<WhoisRequest>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var req = callInfo.ArgAt<WhoisRequest>(0);
                return new ProtocolResponse
                {
                    RawContent = "{}",
                    Protocol = LookupProtocol.Rdap,
                    Response = new DomainInfo
                    {
                        DomainName = new HostName(req.Query),
                        Status = RegistrationStatus.Found,
                    },
                    Diagnostics = new LookupDiagnostics(),
                };
            });

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            rdapRegistry,
            ianaLookup,
            [whoisClient, rdapClient]);

        var result = await lookup.Lookup(".example.com");

        // The leading dot should be stripped before querying
        await rdapClient.Received(1).Query(
            Arg.Is<WhoisRequest>(r => r.Query == "example.com"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Lookup_EmptyQuery_ThrowsArgumentNullException()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);

        var lookup = new WhoisLookup(new WhoisOptions(), rdapRegistry, ianaLookup, [whoisClient, rdapClient]);

        await Assert.ThrowsAsync<ArgumentNullException>(() => lookup.Lookup(string.Empty));
    }

    [Fact]
    public async Task Lookup_RdapProtocol_QueriesRegistryOnlyOnce()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();
        rdapRegistry.GetBaseUrl("com", Arg.Any<CancellationToken>())
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

        var request = new WhoisRequest("google.com") { PreferredProtocol = ProtocolPreference.Rdap };

        var lookup = new WhoisLookup(
            new WhoisOptions(),
            rdapRegistry,
            ianaLookup,
            [whoisClient, rdapClient]);

        await lookup.Lookup(request);

        await rdapRegistry.Received(1).GetBaseUrl("com", Arg.Any<CancellationToken>());
    }

    [Fact]
    public void ClearCache_DelegatesToBothCaches()
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        var ianaLookup = Substitute.For<IIanaServerLookup>();

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);

        var lookup = new WhoisLookup(new WhoisOptions(), rdapRegistry, ianaLookup, [whoisClient, rdapClient]);

        lookup.ClearCache();

        rdapRegistry.Received(1).ClearCache();
        ianaLookup.Received(1).ClearCache();
    }
}
