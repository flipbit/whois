using NSubstitute;
using Xunit;
using Whois.Refresh.Domain;
using Whois.Refresh.Infrastructure;

namespace Whois.Refresh.Tests;

public class DetectCommandTests
{
    private static Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>> MakeResults(
        string server, string tld, string status, string domain, DomainResult result)
    {
        return new Dictionary<string, IDictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>>(StringComparer.Ordinal)
        {
            [server] = new Dictionary<string, IDictionary<string, IDictionary<string, DomainResult>>>(StringComparer.Ordinal)
            {
                [tld] = new Dictionary<string, IDictionary<string, DomainResult>>(StringComparer.Ordinal)
                {
                    [status] = new Dictionary<string, DomainResult>(StringComparer.Ordinal)
                    {
                        [domain] = result,
                    },
                },
            },
        };
    }

    [Fact]
    public async Task DetectAsync_WithBreakages_InvokesDriftReporter()
    {
        var reporter = Substitute.For<IDriftReporter>();
        var fileSystem = Substitute.For<IFileSystem>();

        var baseline = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow.AddDays(-7),
            Results = MakeResults("whois.nic.uk", "uk", "found", "google.co.uk", new DomainResult
            {
                Timestamp = DateTimeOffset.UtcNow.AddDays(-7),
                MatchedTemplate = "whois.nic.uk/uk/found/01",
                ExtractedFields = ["DomainName", "Registrar"],
                Error = null,
            }),
        };

        var current = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = MakeResults("whois.nic.uk", "uk", "found", "google.co.uk", new DomainResult
            {
                Timestamp = DateTimeOffset.UtcNow,
                MatchedTemplate = null,
                ExtractedFields = [],
                Error = null,
            }),
        };

        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>(StringComparer.Ordinal)
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, IList<string>>(StringComparer.Ordinal)
            {
                ["found"] = ["google.co.uk"],
            }),
        });

        // Baseline is read via git, not directly from the file system
        fileSystem.GitReadHeadAsync("/repo", "tools/Whois.Refresh/refresh-results.json", Arg.Any<CancellationToken>())
            .Returns(RefreshResults.Serialize(baseline));

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(current, "/repo", "tools/Whois.Refresh", CancellationToken.None);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NoMatch, entries[0].Classification);

        await reporter.Received(1).ReportAsync(
            Arg.Is<IList<DriftEntry>>(e => e.Count == 1),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DetectAsync_NoDrift_DoesNotInvokeReporter()
    {
        var reporter = Substitute.For<IDriftReporter>();
        var fileSystem = Substitute.For<IFileSystem>();

        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = MakeResults("whois.nic.uk", "uk", "found", "google.co.uk", new DomainResult
            {
                Timestamp = DateTimeOffset.UtcNow,
                MatchedTemplate = "whois.nic.uk/uk/found/01",
                ExtractedFields = ["DomainName", "Registrar"],
                Error = null,
            }),
        };

        fileSystem.GitReadHeadAsync("/repo", "tools/Whois.Refresh/refresh-results.json", Arg.Any<CancellationToken>())
            .Returns(RefreshResults.Serialize(results));

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(results, "/repo", "tools/Whois.Refresh", CancellationToken.None);

        Assert.Empty(entries);
        await reporter.DidNotReceive().ReportAsync(
            Arg.Any<IList<DriftEntry>>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DetectAsync_NoBaselineInGit_AllEntriesAreNew()
    {
        var reporter = Substitute.For<IDriftReporter>();
        var fileSystem = Substitute.For<IFileSystem>();

        var current = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = MakeResults("whois.nic.uk", "uk", "found", "google.co.uk", new DomainResult
            {
                Timestamp = DateTimeOffset.UtcNow,
                MatchedTemplate = "whois.nic.uk/uk/found/01",
                ExtractedFields = ["DomainName"],
                Error = null,
            }),
        };

        // Simulate file not tracked in git (git show returns null)
        fileSystem.GitReadHeadAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(current, "/repo", "tools/Whois.Refresh", CancellationToken.None);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NewEntry, entries[0].Classification);
        // New entries don't trigger PR
        await reporter.DidNotReceive().ReportAsync(
            Arg.Any<IList<DriftEntry>>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
