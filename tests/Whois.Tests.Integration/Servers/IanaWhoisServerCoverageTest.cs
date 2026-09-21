using Whois.Net;
using Xunit;
using Xunit.Abstractions;

namespace Whois.Servers;

/// <summary>
/// Verifies that every TLD with a WHOIS parsing template can resolve
/// a WHOIS server via IANA. Collects all failures before asserting so
/// the output shows every gap at once.
/// </summary>
public class IanaWhoisServerCoverageTest
{
    private readonly ITestOutputHelper _output;

    public IanaWhoisServerCoverageTest(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task AllTemplateTlds_ResolveWhoisServer()
    {
        var tlds = GetTemplateTlds();
        _output.WriteLine($"Found {tlds.Count} unique TLDs with WHOIS templates");

        var lookup = new IanaServerLookup(new TcpReader(), new WhoisOptions
        {
            TimeoutSeconds = 10,
        });

        var failures = new List<(string Tld, string Server, string Reason)>();
        var successes = new List<(string Tld, string Server, string WhoisServer)>();

        foreach (var (tld, server) in tlds.OrderBy(x => x.Tld, StringComparer.Ordinal))
        {
            string? whoisServer;
            try
            {
                whoisServer = await lookup.GetWhoisServer(tld, CancellationToken.None);
            }
            catch (WhoisException ex)
            {
                failures.Add((tld, server, $"WhoisException: {ex.Message}"));
                continue;
            }

            if (whoisServer == null)
            {
                failures.Add((tld, server, "IANA returned no WHOIS server (empty whois: field)"));
            }
            else
            {
                successes.Add((tld, server, whoisServer));
            }
        }

        _output.WriteLine("");
        _output.WriteLine($"=== Results: {successes.Count} passed, {failures.Count} failed ===");
        _output.WriteLine("");

        foreach (var (tld, server, whoisServer) in successes)
        {
            _output.WriteLine($"  OK: .{tld} -> {whoisServer} (template server: {server})");
        }

        if (failures.Count > 0)
        {
            _output.WriteLine("");
            _output.WriteLine("=== FAILURES ===");
            _output.WriteLine("");
            foreach (var (tld, server, reason) in failures)
            {
                _output.WriteLine($"  FAIL: .{tld} (template server: {server}) -- {reason}");
            }
        }

        Assert.True(failures.Count == 0,
            $"{failures.Count} TLD(s) have WHOIS templates but no IANA WHOIS server:\n" +
            string.Join('\n', failures.Select(f => $"  .{f.Tld} ({f.Server}): {f.Reason}")));
    }

    /// <summary>
    /// Extracts unique (TLD, server) pairs from the Resources directory structure.
    /// Layout: Resources/{server}/{tld}/{status}/{file}.txt
    /// Skips generic/catch-all templates and shared templates (centralnic).
    /// </summary>
    private static List<(string Tld, string Server)> GetTemplateTlds()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<(string Tld, string Server)>();

        // Skip directories that aren't real server/TLD mappings
        var skipServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "generic",
            "whois.centralnic.com",
            "whois.iana.org",
        };

        var solutionDir = FindSolutionDirectory();
        var resourcesDir = Path.Combine(solutionDir, "src", "Whois", "Resources");

        foreach (var serverDir in Directory.GetDirectories(resourcesDir))
        {
            var serverName = Path.GetFileName(serverDir);
            if (skipServers.Contains(serverName)) continue;

            foreach (var tldDir in Directory.GetDirectories(serverDir))
            {
                var tld = Path.GetFileName(tldDir);

                // Skip multi-level TLDs (e.g. co.za) -- IANA only knows the parent TLD,
                // and the real lookup extracts the last label from the domain anyway
                if (tld.Contains('.')) continue;

                if (seen.Add(tld))
                {
                    result.Add((tld, serverName));
                }
            }
        }

        return result;
    }

    private static string FindSolutionDirectory()
    {
        var dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir, "Whois.sln")))
                return dir;
            dir = Path.GetDirectoryName(dir);
        }

        throw new InvalidOperationException("Could not find Whois.sln in parent directories");
    }
}
