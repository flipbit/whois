using System.Text.RegularExpressions;

namespace WhoisRefresh.Domain;

public record SampleDomainEntry(string Server, string Tld, string Status, string Filename, string DomainName);

public static partial class TestFileParser
{
    // Matches: SampleReader.Read("server", "tld", "status", "filename")
    [GeneratedRegex("""SampleReader\.Read\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)""")]
    private static partial Regex SampleReaderPattern();

    // Matches: response.DomainName.ToString() in an Assert.Equal
    [GeneratedRegex("""Assert\.Equal\("([^"]+)",\s*response\.DomainName\.ToString\(\)\)""")]
    private static partial Regex DomainNameAssertionPattern();

    public static IList<SampleDomainEntry> ExtractDomains(string testFileContent)
    {
        var results = new List<SampleDomainEntry>();
        var lines = testFileContent.Split('\n');

        string? currentServer = null;
        string? currentTld = null;
        string? currentStatus = null;
        string? currentFilename = null;

        foreach (var line in lines)
        {
            var sampleMatch = SampleReaderPattern().Match(line);
            if (sampleMatch.Success)
            {
                currentServer = sampleMatch.Groups[1].Value;
                currentTld = sampleMatch.Groups[2].Value;
                currentStatus = sampleMatch.Groups[3].Value;
                currentFilename = sampleMatch.Groups[4].Value;
                continue;
            }

            var domainMatch = DomainNameAssertionPattern().Match(line);
            if (domainMatch.Success && currentServer != null)
            {
                var domainName = domainMatch.Groups[1].Value;
                results.Add(new SampleDomainEntry(
                    currentServer, currentTld!, currentStatus!, currentFilename!, domainName));
                // Reset so we don't double-match
                currentServer = null;
                currentTld = null;
                currentStatus = null;
                currentFilename = null;
            }
        }

        return results;
    }

    public static DomainRegistryData BuildRegistry(IList<SampleDomainEntry> entries)
    {
        var servers = new Dictionary<string, ServerEntry>(StringComparer.Ordinal);

        var grouped = entries.GroupBy(e => e.Server, StringComparer.Ordinal);

        foreach (var serverGroup in grouped)
        {
            var serverName = serverGroup.Key;
            var tld = serverGroup.First().Tld;
            var domains = new Dictionary<string, IList<string>>(StringComparer.Ordinal);

            foreach (var statusGroup in serverGroup.GroupBy(e => e.Status, StringComparer.Ordinal))
            {
                IList<string> uniqueDomains = statusGroup
                    .Select(e => e.DomainName)
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToList();
                domains[statusGroup.Key] = uniqueDomains;
            }

            servers[serverName] = new ServerEntry(tld, IsStatic: false, RateGroup: null, domains);
        }

        return new DomainRegistryData(servers);
    }
}
