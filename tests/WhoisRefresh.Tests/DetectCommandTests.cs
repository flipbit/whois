using NSubstitute;
using Xunit;
using WhoisRefresh.Domain;
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Tests;

public class DetectCommandTests
{
    [Fact]
    public async Task DetectAsync_WithBreakages_InvokesDriftReporter()
    {
        var reporter = Substitute.For<IDriftReporter>();
        var fileSystem = Substitute.For<IFileSystem>();

        var baseline = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow.AddDays(-7),
            Results = new()
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow.AddDays(-7),
                                MatchedTemplate = "whois.nic.uk/uk/found/01",
                                ExtractedFields = ["DomainName", "Registrar"],
                                Error = null
                            }
                        }
                    }
                }
            }
        };

        var current = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new()
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = null,
                                ExtractedFields = [],
                                Error = null
                            }
                        }
                    }
                }
            }
        };

        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        // Baseline is read via git, not directly from the file system
        fileSystem.GitReadHeadAsync("/repo", "tools/WhoisRefresh/refresh-results.json", Arg.Any<CancellationToken>())
            .Returns(RefreshResults.Serialize(baseline));

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(current, registry, "/repo", "tools/WhoisRefresh", CancellationToken.None);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NoMatch, entries[0].Classification);

        await reporter.Received(1).ReportAsync(
            Arg.Is<List<DriftEntry>>(e => e.Count == 1),
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
            Results = new()
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = "whois.nic.uk/uk/found/01",
                                ExtractedFields = ["DomainName", "Registrar"],
                                Error = null
                            }
                        }
                    }
                }
            }
        };

        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        fileSystem.GitReadHeadAsync("/repo", "tools/WhoisRefresh/refresh-results.json", Arg.Any<CancellationToken>())
            .Returns(RefreshResults.Serialize(results));

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(results, registry, "/repo", "tools/WhoisRefresh", CancellationToken.None);

        Assert.Empty(entries);
        await reporter.DidNotReceive().ReportAsync(
            Arg.Any<List<DriftEntry>>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DetectAsync_NoBaselineInGit_AllEntriesAreNew()
    {
        var reporter = Substitute.For<IDriftReporter>();
        var fileSystem = Substitute.For<IFileSystem>();

        var current = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new()
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = "whois.nic.uk/uk/found/01",
                                ExtractedFields = ["DomainName"],
                                Error = null
                            }
                        }
                    }
                }
            }
        };

        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        // Simulate file not tracked in git (git show returns null)
        fileSystem.GitReadHeadAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((string?)null);

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(current, registry, "/repo", "tools/WhoisRefresh", CancellationToken.None);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NewEntry, entries[0].Classification);
        // New entries don't trigger PR
        await reporter.DidNotReceive().ReportAsync(
            Arg.Any<List<DriftEntry>>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
