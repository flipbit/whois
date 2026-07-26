using Xunit;
using Whois.Refresh.Domain;

namespace Whois.Refresh.Tests;

public class BootstrapCommandTests
{
    [Fact]
    public void ExtractDomains_StandardTestFile_ExtractsDomainAndSampleInfo()
    {
        var testContent = """
            public class UkParsingTests : ParsingTests
            {
                [Fact]
                public void Test_found()
                {
                    var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found.txt");
                    var response = parser.Parse("whois.nic.uk", sample);
                    Assert.Equal("netbenefit.co.uk", response.DomainName.ToString());
                }

                [Fact]
                public void Test_not_found()
                {
                    var sample = SampleReader.Read("whois.nic.uk", "uk", "not-found", "not_found.txt");
                    var response = parser.Parse("whois.nic.uk", sample);
                    Assert.Equal("u34jedzcq.co.uk", response.DomainName.ToString());
                }
            }
            """;

        var entries = TestFileParser.ExtractDomains(testContent);

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e =>
            string.Equals(e.Server, "whois.nic.uk", StringComparison.Ordinal) &&
            string.Equals(e.Tld, "uk", StringComparison.Ordinal) &&
            string.Equals(e.Status, "found", StringComparison.Ordinal) &&
            string.Equals(e.DomainName, "netbenefit.co.uk", StringComparison.Ordinal));
        Assert.Contains(entries, e =>
            string.Equals(e.Server, "whois.nic.uk", StringComparison.Ordinal) &&
            string.Equals(e.Tld, "uk", StringComparison.Ordinal) &&
            string.Equals(e.Status, "not-found", StringComparison.Ordinal) &&
            string.Equals(e.DomainName, "u34jedzcq.co.uk", StringComparison.Ordinal));
    }

    [Fact]
    public void ExtractDomains_ThrottledWithNoDomainAssertion_SkipsEntry()
    {
        var testContent = """
            [Fact]
            public void Test_throttled()
            {
                var sample = SampleReader.Read("kero.yachay.pe", "pe", "throttled", "throttled.txt");
                var response = parser.Parse("kero.yachay.pe", sample);
                Assert.Equal(WhoisStatus.Throttled, response.Status);
            }
            """;

        var entries = TestFileParser.ExtractDomains(testContent);

        Assert.Empty(entries);
    }

    [Fact]
    public void ExtractDomains_MultipleSamplesForSameStatus_ExtractsAll()
    {
        var testContent = """
            [Fact]
            public void Test_found()
            {
                var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found.txt");
                var response = parser.Parse("whois.nic.uk", sample);
                Assert.Equal("netbenefit.co.uk", response.DomainName.ToString());
            }

            [Fact]
            public void Test_found_registrant_type_individual()
            {
                var sample = SampleReader.Read("whois.nic.uk", "uk", "found", "found_registrant_type_individual.txt");
                var response = parser.Parse("whois.nic.uk", sample);
                Assert.Equal("bedandbreakfastsearcher.co.uk", response.DomainName.ToString());
            }
            """;

        var entries = TestFileParser.ExtractDomains(testContent);

        Assert.Equal(2, entries.Count);
        Assert.Contains(entries, e => string.Equals(e.DomainName, "netbenefit.co.uk", StringComparison.Ordinal));
        Assert.Contains(entries, e => string.Equals(e.DomainName, "bedandbreakfastsearcher.co.uk", StringComparison.Ordinal));
    }

    [Fact]
    public void ExtractDomains_DeduplicatesSameDomain()
    {
        // Same domain can appear in multiple test methods (e.g. found + not_found_status_available)
        var testContent = """
            [Fact]
            public void Test_not_found()
            {
                var sample = SampleReader.Read("whois.nic.uk", "uk", "not-found", "not_found.txt");
                var response = parser.Parse("whois.nic.uk", sample);
                Assert.Equal("u34jedzcq.co.uk", response.DomainName.ToString());
            }

            [Fact]
            public void Test_not_found_status_available()
            {
                var sample = SampleReader.Read("whois.nic.uk", "uk", "not-found", "not_found_status_available.txt");
                var response = parser.Parse("whois.nic.uk", sample);
                Assert.Equal("u34jedzcq.co.uk", response.DomainName.ToString());
            }
            """;

        var entries = TestFileParser.ExtractDomains(testContent);

        // Both entries are returned  -  deduplication happens at registry generation level
        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public void BuildRegistry_GroupsByServerAndStatus_DeduplicatesDomains()
    {
        IList<SampleDomainEntry> entries =
        [
            new("whois.nic.uk", "uk", "found", "found.txt", "netbenefit.co.uk"),
            new("whois.nic.uk", "uk", "found", "found_other.txt", "netbenefit.co.uk"),
            new("whois.nic.uk", "uk", "found", "found_bbc.txt", "bbc.co.uk"),
            new("whois.nic.uk", "uk", "not-found", "not_found.txt", "u34jedzcq.co.uk"),
        ];

        var registry = TestFileParser.BuildRegistry(entries);

        var server = registry.Servers["whois.nic.uk"];
        Assert.Equal("uk", server.Tld);
        Assert.Equal(2, server.Domains["found"].Count); // deduplicated
        Assert.Contains("netbenefit.co.uk", server.Domains["found"]);
        Assert.Contains("bbc.co.uk", server.Domains["found"]);
        Assert.Single(server.Domains["not-found"]);
    }
}
