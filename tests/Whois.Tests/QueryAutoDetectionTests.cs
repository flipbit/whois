using System.Net;
using NSubstitute;
using Whois.Protocols;
using Whois.Servers;
using Xunit;

namespace Whois;

public class QueryAutoDetectionTests
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("test.org")]
    public async Task Query_DomainString_DelegatesToDomainLookup(string domain)
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        rdapRegistry.GetBaseUrl(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("https://rdap.example.com/");

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);
        rdapClient.Query(Arg.Any<LookupRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ProtocolResponse
            {
                RawContent = "test",
                Protocol = LookupProtocol.Rdap,
                Response = new DomainInfo { Status = RegistrationStatus.Found },
                Diagnostics = new LookupDiagnostics(),
            });

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var ianaLookup = Substitute.For<IIanaServerLookup>();
        var lookup = new WhoisLookup(
            new WhoisOptions(), rdapRegistry, ianaLookup,
            new List<IProtocolClient> { whoisClient, rdapClient });

        var result = await lookup.Query(domain);

        Assert.IsType<DomainInfo>(result.Response);
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("2001:4860:4860::8888")]
    public async Task Query_IpString_DelegatesToIpLookup(string ip)
    {
        var rdapRegistry = Substitute.For<IRdapRegistryCache>();
        rdapRegistry.GetBaseUrl(Arg.Any<IPAddress>(), Arg.Any<CancellationToken>())
            .Returns("https://rdap.arin.net/registry/");

        var rdapClient = Substitute.For<IProtocolClient>();
        rdapClient.Protocol.Returns(LookupProtocol.Rdap);
        rdapClient.Query(Arg.Any<LookupRequest>(), Arg.Any<CancellationToken>())
            .Returns(new ProtocolResponse
            {
                RawContent = "{}",
                Protocol = LookupProtocol.Rdap,
                Response = new IpInfo { Status = RegistrationStatus.Found },
                Diagnostics = new LookupDiagnostics(),
            });

        var whoisClient = Substitute.For<IProtocolClient>();
        whoisClient.Protocol.Returns(LookupProtocol.Whois);

        var ianaLookup = Substitute.For<IIanaServerLookup>();
        var lookup = new WhoisLookup(
            new WhoisOptions(), rdapRegistry, ianaLookup,
            new List<IProtocolClient> { whoisClient, rdapClient });

        var result = await lookup.Query(ip);

        Assert.IsType<IpInfo>(result.Response);
    }
}
