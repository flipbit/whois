using NSubstitute;
using System.Text;
using Whois.Net;
using Whois.Parsers;
using Whois.Protocols;
using Whois.Servers;
using Xunit;

namespace Whois;

public class WhoisProtocolClientTests
{
    [Fact]
    public async Task Query_ValidDomain_ReturnsProtocolResponse()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var sampleReader = new SampleReader();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.markmonitor.com");

        var sample = sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt");
        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(sample);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("google.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal(LookupProtocol.Whois, response.Protocol);
        Assert.Equal("google.com", response.Response.DomainName!.ToString());
        Assert.Equal(RegistrationStatus.Found, response.Response.Status);
        Assert.NotEmpty(response.RawContent);
    }

    [Fact]
    public async Task Query_FollowsReferralChain()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var sampleReader = new SampleReader();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.verisign-grs.com");

        var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found", "found_status_registered.txt");
        var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt");

        tcpReader
            .Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(intermediateResult);
        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(authoritativeResult);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("google.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal("google.com", response.Response.DomainName!.ToString());
        Assert.True(response.Diagnostics.ReferralChain.Count >= 1);
    }
}
