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
    private static readonly Encoding DefaultEncoding = Encoding.UTF8;
    private const int DefaultTimeout = 10;

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
            .Read("whois.markmonitor.com", 43, "google.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
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
            .Read("whois.verisign-grs.com", 43, "google.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(intermediateResult);
        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(authoritativeResult);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("google.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal("google.com", response.Response.DomainName!.ToString());
        Assert.Equal(2, response.Diagnostics.ReferralChain.Count);
    }

    [Fact]
    public async Task Query_DomainEndingInJpWithoutDot_DoesNotAddEnglishSuffix()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var sampleReader = new SampleReader();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("nejp", Arg.Any<CancellationToken>())
            .Returns("whois.example.com");

        var sample = sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt");
        tcpReader
            .Read("whois.example.com", 43, "example.nejp", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(sample);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.nejp");

        await client.Query(request, CancellationToken.None);

        // Verify that the query sent to tcpReader was without the /e suffix
        await tcpReader.Received(1).Read(
            "whois.example.com", 43, "example.nejp", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Query_JpDomain_AppendsEnglishSuffix()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("jp", Arg.Any<CancellationToken>())
            .Returns("whois.jprs.jp");

        // Return a simple WHOIS response with no referral
        var content = "Domain Name: example.jp\r\nRegistrar: Example Registrar\r\n";
        tcpReader
            .Read("whois.jprs.jp", 43, "example.jp/e", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(content);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.jp");

        await client.Query(request, CancellationToken.None);

        // The /e suffix must be appended when the query ends exactly with .jp
        await tcpReader.Received(1).Read(
            "whois.jprs.jp", 43, "example.jp/e", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Query_ReferralLoopDetected_StopsChain()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.server-a.com");

        // server-a refers to server-b
        var serverAContent = "Domain Name: example.com\r\nRegistrar WHOIS Server: whois.server-b.com\r\nRegistrar: Server A\r\n";
        // server-b refers back to server-a (loop)
        var serverBContent = "Domain Name: example.com\r\nRegistrar WHOIS Server: whois.server-a.com\r\nRegistrar: Server B\r\n";

        tcpReader
            .Read("whois.server-a.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(serverAContent);
        tcpReader
            .Read("whois.server-b.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(serverBContent);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.com");

        var response = await client.Query(request, CancellationToken.None);

        // Loop is detected after visiting server-a and server-b; server-a is not queried again
        await tcpReader.Received(1).Read(
            "whois.server-a.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());
        await tcpReader.Received(1).Read(
            "whois.server-b.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());

        // Referral chain contains both servers visited
        Assert.Equal(2, response.Diagnostics.ReferralChain.Count);
    }

    [Fact]
    public async Task Query_DepthLimitExceeded_StopsChain()
    {
        // Each server in the chain refers to the next unique server; once 10 unique
        // servers have been visited the depth guard fires and the loop terminates.
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.node-0.com");

        // Dynamic callback: each call receives a server index via the hostname and
        // returns content that refers to the next server in the chain.
        tcpReader
            .Read(Arg.Any<string>(), 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .ReturnsForAnyArgs(callInfo =>
            {
                var server = (string)callInfo[0];
                // Parse the current index from the hostname "whois.node-N.com"
                var part = server
                    .Replace("whois.node-", string.Empty, StringComparison.Ordinal)
                    .Replace(".com", string.Empty, StringComparison.Ordinal);
                var index = int.Parse(part, System.Globalization.CultureInfo.InvariantCulture);
                var nextIndex = index + 1;
                // Return content pointing to the next unique server
                return FormattableString.Invariant(
                    $"Domain Name: example.com\r\nRegistrar WHOIS Server: whois.node-{nextIndex}.com\r\nRegistrar: Node {index}\r\n");
            });

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.com");

        // This must complete rather than loop forever; the depth guard (> 10) stops it.
        var response = await client.Query(request, CancellationToken.None);

        // 11 unique servers are visited (indices 0..10) before the guard breaks the loop
        Assert.Equal(11, response.Diagnostics.ReferralChain.Count);
    }

    [Fact]
    public async Task Query_CustomWhoisServer_BypassesBootstrap()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        var content = "Domain Name: example.com\r\nRegistrar: Custom Registrar\r\n";
        tcpReader
            .Read("whois.custom.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(content);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.com")
        {
            WhoisServer = new HostName("whois.custom.com"),
        };

        await client.Query(request, CancellationToken.None);

        // Bootstrap must never be consulted when WhoisServer is supplied explicitly
        await bootstrap.DidNotReceiveWithAnyArgs().GetWhoisServer(default!, default);
        await tcpReader.Received(1).Read(
            "whois.custom.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Query_FollowReferrerFalse_StopsAfterFirstServer()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.first.com");

        // First server response contains a referral to a second server
        var firstContent = "Domain Name: example.com\r\nRegistrar WHOIS Server: whois.second.com\r\nRegistrar: First Registrar\r\n";
        tcpReader
            .Read("whois.first.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(firstContent);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.com")
        {
            FollowReferrer = false,
        };

        var response = await client.Query(request, CancellationToken.None);

        // Only the first server should be queried
        await tcpReader.Received(1).Read(
            "whois.first.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());
        await tcpReader.DidNotReceive().Read(
            "whois.second.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>());

        Assert.Equal(1, response.Diagnostics.ReferralChain.Count);
    }

    [Fact]
    public async Task Query_EmptyResponseFromServer_ReturnsUnknownStatus()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("com", Arg.Any<CancellationToken>())
            .Returns("whois.empty.com");

        // Server returns empty content; no fields can be parsed
        tcpReader
            .Read("whois.empty.com", 43, "example.com", DefaultEncoding, DefaultTimeout, Arg.Any<CancellationToken>())
            .Returns(string.Empty);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.com");

        var response = await client.Query(request, CancellationToken.None);

        Assert.Equal(RegistrationStatus.Unknown, response.Response.Status);
    }

    [Fact]
    public async Task Query_NoBootstrapServerFound_ThrowsWhoisException()
    {
        var tcpReader = Substitute.For<ITcpReader>();
        var bootstrap = Substitute.For<IBootstrapRegistry>();
        var parser = new WhoisParser();
        var options = new WhoisOptions();

        bootstrap.GetWhoisServer("unknown", Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var client = new WhoisProtocolClient(tcpReader, bootstrap, parser, options);
        var request = new WhoisRequest("example.unknown");

        var ex = await Assert.ThrowsAsync<WhoisException>(() =>
            client.Query(request, CancellationToken.None));

        Assert.Contains("unknown", ex.Message, StringComparison.Ordinal);
        await tcpReader.DidNotReceiveWithAnyArgs().Read(default!, default, default!, default!, default, default);
    }
}
