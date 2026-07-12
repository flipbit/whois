using System.Text;
using NSubstitute;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;
using Whois.Templates;
using Xunit;

namespace Whois;

public class WhoisLookupTest
{
    private readonly WhoisLookup lookup;

    private readonly IWhoisServerLookup whoisServerLookup;
    private readonly ITcpReader tcpReader;
    private readonly SampleReader sampleReader;

    public WhoisLookupTest()
    {
        whoisServerLookup = Substitute.For<IWhoisServerLookup>();
        tcpReader = Substitute.For<ITcpReader>();
        sampleReader = new SampleReader();

        lookup = new WhoisLookup
        {
            TcpReader = tcpReader,
            ServerLookup = whoisServerLookup,
        };
    }

    [Fact]
    public async Task TestLookupDomain()
    {
        var request = new WhoisRequest("google.com");

        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com"), },
        };

        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);

        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt"));

        var result = await lookup.Lookup(request);

        Assert.Equal("google.com", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);
    }

    [Fact]
    public async Task TestLookupDomainWithIntermediateServer()
    {
        var request = new WhoisRequest("google.com");
        var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found", "found_status_registered.txt");
        var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt");

        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.verisign-grs.com"), },
        };

        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);

        tcpReader
            .Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(intermediateResult);

        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(authoritativeResult);

        var result = await lookup.Lookup(request);

        Assert.Equal("google.com", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);

        Assert.Equal(authoritativeResult, result.Content);
        Assert.Equal(intermediateResult, result.Referrer.Content);
        Assert.Equal(rootServer, result.Referrer.Referrer);
    }

    [Fact]
    public async Task TestLookupDomainDontFollowReferrer()
    {
        var request = new WhoisRequest { Query = "google.com", FollowReferrer = false };
        var intermediateResult = sampleReader.Read("whois.verisign-grs.com", "com", "found", "found_status_registered.txt");

        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.verisign-grs.com"), },
        };

        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);

        tcpReader
            .Read("whois.verisign-grs.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(intermediateResult);

        var result = await lookup.Lookup(request);

        Assert.Equal("google.com", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);

        Assert.Equal(intermediateResult, result.Content);
        Assert.Equal(rootServer, result.Referrer);
    }

    [Fact]
    public async Task TestLookupDomainSpecifyRootServer()
    {
        var request = new WhoisRequest { Query = "google.com", WhoisServer = "whois.markmonitor.com" };
        var authoritativeResult = sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt");

        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(authoritativeResult);

        var result = await lookup.Lookup(request);

        Assert.Equal("google.com", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);

        Assert.Equal(authoritativeResult, result.Content);
        Assert.Equal("whois.markmonitor.com", result.Referrer.WhoisServer.Value);

        await whoisServerLookup.DidNotReceive().Lookup(request, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TestLookupTld()
    {
        var request = new WhoisRequest(".com");

        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com"), },
        };

        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);

        var result = await lookup.Lookup(request);

        Assert.Equal(rootServer, result);
    }

    [Fact]
    public async Task TestLookupDomainWithEmptyQuery()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => lookup.Lookup(string.Empty));
    }

    [Fact]
    public async Task TestLookupDomainWithNullQuery()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => lookup.Lookup(null, Encoding.UTF8));
    }

    /// <summary>
    /// When looking up a WHOIS domain, we follow a chain of responses:
    ///
    ///   Root Server > Intermediate Server > Authoritative Server
    ///
    /// Sometimes the response at the end of the chain contains less information than an
    /// intermediate step.  In this case, we return the response with the most information
    /// </summary>
    [Fact]
    public async Task TestLookupDomainUseBestResponse()
    {
        // Setup our initial request
        var request = new WhoisRequest { Query = "fark.co", FollowReferrer = true };

        // Setup the inital root server response
        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("co"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.nic.co"), },
        };
        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);

        // Setup the intermediate server response
        var intermediateResult = sampleReader.Read("whois.nic.co", "co", "found", "fark.co.txt");
        tcpReader
            .Read("whois.nic.co", 43, "fark.co", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(intermediateResult);

        // Setup the authoritative server response
        // Note: this contains less data than the intermediate response, so should be ignored
        var authoritativeResult = sampleReader.Read("whois.dynadot.com", "co", "found", "fark.co.txt");
        tcpReader
            .Read("whois.dynadot.com", 43, "fark.co", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(authoritativeResult);

        var result = await lookup.Lookup(request);

        Assert.Equal("fark.co", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);

        Assert.Equal(intermediateResult, result.Content);
        Assert.Equal(rootServer, result.Referrer);
    }

    [Fact]
    public void TemplateStatus_DefaultsToEmbedded()
    {
        var instance = new WhoisLookup();

        Assert.Equal(TemplateSource.Embedded, instance.TemplateStatus.Source);
        Assert.Equal("embedded", instance.TemplateStatus.CurrentVersion);
    }

    [Fact]
    public async Task UpdateTemplates_DelegatesToPackProvider()
    {
        var packProvider = Substitute.For<ITemplatePackProvider>();
        var parser = new WhoisParser();
        var expected = new TemplateUpdateResult(TemplateUpdateOutcome.AlreadyUpToDate, "1.0.0", null);
        packProvider.CheckForUpdate(Arg.Any<CancellationToken>()).Returns(expected);

        var instance = new WhoisLookup(packProvider, parser)
        {
            TcpReader = tcpReader,
            ServerLookup = whoisServerLookup,
        };

        var result = await instance.UpdateTemplates();

        Assert.Equal(expected, result);
        await packProvider.Received(1).CheckForUpdate(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Lookup_WithAutoUpdate_TriggersBackgroundCheck()
    {
        var packProvider = Substitute.For<ITemplatePackProvider>();
        var parser = new WhoisParser();
        var triggered = new ManualResetEventSlim(false);

        packProvider.CheckForUpdate(Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                triggered.Set();
                return new TemplateUpdateResult(TemplateUpdateOutcome.AlreadyUpToDate, "1.0.0", null);
            });

        packProvider.Status.Returns(new TemplateStatus("embedded", TemplateSource.Embedded, null, null, null, false));

        var request = new WhoisRequest("google.com");
        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com") },
        };
        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);
        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt"));

        var instance = new WhoisLookup(packProvider, parser)
        {
            Options = { AutoUpdateTemplates = true },
            TcpReader = tcpReader,
            ServerLookup = whoisServerLookup,
        };

        await instance.Lookup(request);

        Assert.True(triggered.Wait(TimeSpan.FromSeconds(5)), "CheckForUpdate was not called within timeout");
    }

    [Fact]
    public async Task Lookup_MultipleCallsWithAutoUpdate_TriggersOnce()
    {
        var packProvider = Substitute.For<ITemplatePackProvider>();
        var parser = new WhoisParser();
        var callCount = 0;
        var firstCallStarted = new ManualResetEventSlim(false);

        packProvider.CheckForUpdate(Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                Interlocked.Increment(ref callCount);
                firstCallStarted.Set();
                return new TemplateUpdateResult(TemplateUpdateOutcome.AlreadyUpToDate, "1.0.0", null);
            });

        packProvider.Status.Returns(new TemplateStatus("embedded", TemplateSource.Embedded, null, null, null, false));

        var request = new WhoisRequest("google.com");
        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com") },
        };
        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);
        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt"));

        var instance = new WhoisLookup(packProvider, parser)
        {
            Options = { AutoUpdateTemplates = true },
            TcpReader = tcpReader,
            ServerLookup = whoisServerLookup,
        };

        await instance.Lookup(request);
        await instance.Lookup(request);

        firstCallStarted.Wait(TimeSpan.FromSeconds(5));

        // Give the background task a moment to complete
        await Task.Delay(200);

        Assert.Equal(1, callCount);
    }

    [Fact]
    public async Task Lookup_WithAutoUpdate_DoesNotBlockQuery()
    {
        var packProvider = Substitute.For<ITemplatePackProvider>();
        var parser = new WhoisParser();
        var checkForUpdateBlocked = new ManualResetEventSlim(false);
        var checkForUpdateStarted = new ManualResetEventSlim(false);

        packProvider.CheckForUpdate(Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                checkForUpdateStarted.Set();
                // Block until signaled (simulating a long-running update check)
                checkForUpdateBlocked.Wait(TimeSpan.FromSeconds(10));
                return new TemplateUpdateResult(TemplateUpdateOutcome.AlreadyUpToDate, "1.0.0", null);
            });

        packProvider.Status.Returns(new TemplateStatus("embedded", TemplateSource.Embedded, null, null, null, false));

        var request = new WhoisRequest("google.com");
        var rootServer = new WhoisResponse
        {
            DomainName = new HostName("com"),
            Registrar = new Registrar { WhoisServer = new HostName("whois.markmonitor.com") },
        };
        whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);
        tcpReader
            .Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>())
            .Returns(sampleReader.Read("whois.markmonitor.com", "com", "found", "found.txt"));

        var instance = new WhoisLookup(packProvider, parser)
        {
            Options = { AutoUpdateTemplates = true },
            TcpReader = tcpReader,
            ServerLookup = whoisServerLookup,
        };

        // Call Lookup - should return promptly even though CheckForUpdate is blocked
        var lookupTask = instance.Lookup(request);
        var completedWithinTimeout = await Task.WhenAny(
            lookupTask,
            Task.Delay(TimeSpan.FromSeconds(5))
        ) == lookupTask;

        Assert.True(completedWithinTimeout, "Lookup did not complete within timeout - it was blocked by CheckForUpdate");

        var result = await lookupTask;
        Assert.Equal("google.com", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);

        // Signal the background check to complete (cleanup)
        checkForUpdateBlocked.Set();
    }
}
