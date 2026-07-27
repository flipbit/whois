using System.Text;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Whois.Net;
using Whois.Refresh.Domain;
using Whois.Refresh.Infrastructure;
using Xunit;

namespace Whois.Refresh.Tests;

public class RefreshEngineTests
{
    private readonly ITcpReader _tcpReader = Substitute.For<ITcpReader>();
    private readonly IFileSystem _fileSystem = Substitute.For<IFileSystem>();
    private readonly RefreshEngineOptions _options = new(
        SamplesBasePath: "/repo/tests/Whois.Tests/Samples",
        DelayBetweenQueries: TimeSpan.Zero, // no delay in tests
        QueryTimeoutSeconds: 30,
        MaxResponseBytes: 65536);

    private static DomainRegistryData SingleServer(string server, string tld, string status, string domain, bool isStatic = false, string? rateGroup = null) =>
        new(new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            [server] = new(tld, isStatic, rateGroup, new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                [status] = [domain],
            }),
        });

    private WhoisRefreshEngine CreateEngine() => new(_tcpReader, _fileSystem);

    [Fact]
    public async Task RunAsync_SingleDomain_QueriesAndSavesResponse()
    {
        var registry = SingleServer("whois.nic.uk", "uk", "found", "google.co.uk");

        var whoisResponse = "Domain Name: google.co.uk\r\nRegistrar: Test Registrar\r\n";
        _tcpReader.Read("whois.nic.uk", 43, "google.co.uk\r\n", Arg.Any<Encoding>(), 30, Arg.Any<CancellationToken>())
            .Returns(whoisResponse);

        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        // Verify response was saved
        await _fileSystem.Received(1).WriteAllTextAsync(
            "/repo/tests/Whois.Tests/Samples/whois.nic.uk/uk/found/google.co.uk.txt",
            whoisResponse,
            Arg.Any<CancellationToken>());

        // Verify result recorded
        var domainResult = results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.NotNull(domainResult);
        Assert.Null(domainResult.Error);
    }

    [Fact]
    public async Task RunAsync_StaticServer_SkipsQuery()
    {
        var registry = SingleServer("whois.denic.de", "de", "found", "google.de", isStatic: true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        await _tcpReader.DidNotReceive().Read(
            Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
            Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>());

        Assert.Empty(results.Results);
    }

    [Fact]
    public async Task RunAsync_QueryTimeout_RecordsError()
    {
        var registry = SingleServer("whois.nic.uk", "uk", "found", "google.co.uk");

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new OperationCanceledException("Timeout"));

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        var domainResult = results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.NotNull(domainResult.Error);
        Assert.Equal(QueryErrorType.Timeout, domainResult.Error.Type);
    }

    [Fact]
    public async Task RunAsync_ResponseExceedsMaxSize_TruncatesAndRecordsError()
    {
        var registry = SingleServer("whois.nic.uk", "uk", "found", "google.co.uk");

        var largeResponse = new string('x', 200);

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(largeResponse);

        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options with { MaxResponseBytes = 100 }, CancellationToken.None);

        var domainResult = results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.NotNull(domainResult.Error);
        Assert.Equal(QueryErrorType.ResponseTooLarge, domainResult.Error.Type);
    }

    [Fact]
    public async Task RunAsync_PartialFailure_CollectsAllResults()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                ["found"] = ["google.co.uk", "bbc.co.uk"],
            }),
        });

        _tcpReader.Read("whois.nic.uk", 43, "google.co.uk\r\n", Arg.Any<Encoding>(), 30, Arg.Any<CancellationToken>())
            .Returns("Domain Name: google.co.uk\r\n");
        _tcpReader.Read("whois.nic.uk", 43, "bbc.co.uk\r\n", Arg.Any<Encoding>(), 30, Arg.Any<CancellationToken>())
            .ThrowsAsync(new OperationCanceledException("Timeout"));

        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        Assert.Equal(2, results.Results["whois.nic.uk"]["uk"]["found"].Count);
        Assert.Null(results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"].Error);
        Assert.NotNull(results.Results["whois.nic.uk"]["uk"]["found"]["bbc.co.uk"].Error);
    }

    [Fact]
    public async Task RunAsync_RateGroups_QueriesGroupsInParallel()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            ["whois.verisign-grs.com"] = new("com", false, "verisign", new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                ["found"] = ["google.com"],
            }),
            ["ccwhois.verisign-grs.com"] = new("cc", false, "verisign", new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                ["found"] = ["example.cc"],
            }),
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                ["found"] = ["google.co.uk"],
            }),
        });

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns("Domain Name: test\r\n");
        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        Assert.True(results.Results.ContainsKey("whois.verisign-grs.com"));
        Assert.True(results.Results.ContainsKey("ccwhois.verisign-grs.com"));
        Assert.True(results.Results.ContainsKey("whois.nic.uk"));
    }

    [Fact]
    public async Task RunAsync_CreatesDirectoryIfMissing()
    {
        var registry = SingleServer("whois.nic.uk", "uk", "found", "google.co.uk");

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns("Domain Name: google.co.uk\r\n");
        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(false);

        await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        _fileSystem.Received(1).CreateDirectory("/repo/tests/Whois.Tests/Samples/whois.nic.uk/uk/found");
    }
}
