using System.Globalization;
using Spectre.Console.Cli;
using Whois.Net;
using Whois.Refresh.Domain;
using Whois.Refresh.Infrastructure;

namespace Whois.Refresh.Commands;

public class RefreshSettings : CommandSettings
{
    [CommandArgument(0, "<repo-root>")]
    public string RepoRoot { get; set; } = string.Empty;

    [CommandOption("--timeout")]
    public int TimeoutSeconds { get; set; } = 30;

    [CommandOption("--delay")]
    public int DelayMs { get; set; } = 5000;

    [CommandOption("--max-response")]
    public int MaxResponseBytes { get; set; } = 65536;

    [CommandOption("--protocol")]
    public string? Protocol { get; set; }
}

public class RefreshCommand : AsyncCommand<RefreshSettings>
{
    private readonly ITcpReader _tcpReader;
    private readonly IFileSystem _fileSystem;
    private readonly HttpClient _httpClient;

    public RefreshCommand(ITcpReader tcpReader, IFileSystem fileSystem, HttpClient httpClient)
    {
        _tcpReader = tcpReader;
        _fileSystem = fileSystem;
        _httpClient = httpClient;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, RefreshSettings settings)
    {
        var toolDir = Path.Combine(settings.RepoRoot, "tools", "Whois.Refresh");
        var samplesPath = Path.Combine(settings.RepoRoot, "tests", "Whois.Tests", "Samples");

        var parsedProtocol = Enum.TryParse<LookupProtocol>(settings.Protocol, ignoreCase: true, out var p)
            ? (LookupProtocol?)p : null;
        var runWhois = parsedProtocol is null or LookupProtocol.Whois;
        var runRdap = parsedProtocol is null or LookupProtocol.Rdap;

        var whoisSuccesses = 0;
        var whoisErrors = 0;
        var rdapSuccesses = 0;
        var rdapErrors = 0;

        if (runWhois)
        {
            var registryPath = Path.Combine(toolDir, "domains-whois.jsonc");
            var resultsPath = Path.Combine(toolDir, "refresh-results.json");

            if (!File.Exists(registryPath))
            {
                ConsoleOutput.WriteError($"domains-whois.jsonc not found at {registryPath}");
                return 1;
            }

            var registry = await DomainRegistry.LoadFromFileAsync(registryPath).ConfigureAwait(false);
            var queryable = registry.Servers.Where(s => !s.Value.IsStatic).ToList();
            var totalDomains = queryable.SelectMany(s => s.Value.Domains.Values).Sum(d => d.Count);

            ConsoleOutput.WriteInfo(string.Format(CultureInfo.InvariantCulture,
                "WHOIS: querying {0} domains across {1} servers...", totalDomains, queryable.Count));

            var options = new RefreshEngineOptions(
                SamplesBasePath: samplesPath,
                DelayBetweenQueries: TimeSpan.FromMilliseconds(settings.DelayMs),
                QueryTimeoutSeconds: settings.TimeoutSeconds,
                MaxResponseBytes: settings.MaxResponseBytes);

            var engine = new WhoisRefreshEngine(_tcpReader, _fileSystem);
            var results = await engine.RunAsync(registry, options, CancellationToken.None).ConfigureAwait(false);
            results.Prune(registry);

            var json = RefreshResults.Serialize(results);
            await _fileSystem.WriteAllTextAsync(resultsPath, json).ConfigureAwait(false);

            (whoisSuccesses, whoisErrors) = CountResults(results);
        }

        if (runRdap)
        {
            var registryPath = Path.Combine(toolDir, "domains-rdap.jsonc");
            var resultsPath = Path.Combine(toolDir, "refresh-results-rdap.json");

            if (!File.Exists(registryPath))
            {
                ConsoleOutput.WriteError($"domains-rdap.jsonc not found at {registryPath}");
                return 1;
            }

            var registry = await DomainRegistry.LoadFromFileAsync(registryPath).ConfigureAwait(false);
            var queryable = registry.Servers.Where(s => !s.Value.IsStatic).ToList();
            var totalDomains = queryable.SelectMany(s => s.Value.Domains.Values).Sum(d => d.Count);

            ConsoleOutput.WriteInfo(string.Format(CultureInfo.InvariantCulture,
                "RDAP: querying {0} domains across {1} servers...", totalDomains, queryable.Count));

            var options = new RdapRefreshEngineOptions(
                DelayBetweenQueries: TimeSpan.FromMilliseconds(settings.DelayMs),
                QueryTimeoutSeconds: settings.TimeoutSeconds);

            var engine = new RdapRefreshEngine(_httpClient);
            var results = await engine.RunAsync(registry, options, CancellationToken.None).ConfigureAwait(false);
            results.Prune(registry);

            var json = RefreshResults.Serialize(results);
            await _fileSystem.WriteAllTextAsync(resultsPath, json).ConfigureAwait(false);

            (rdapSuccesses, rdapErrors) = CountResults(results);
        }

        // Summary
        var parts = new List<string>();
        if (runWhois)
            parts.Add(string.Format(CultureInfo.InvariantCulture,
                "WHOIS: {0} succeeded, {1} failed", whoisSuccesses, whoisErrors));
        if (runRdap)
            parts.Add(string.Format(CultureInfo.InvariantCulture,
                "RDAP: {0} succeeded, {1} failed", rdapSuccesses, rdapErrors));

        ConsoleOutput.WriteSuccess(string.Format(CultureInfo.InvariantCulture,
            "Refresh complete: {0}", string.Join(". ", parts)));

        var totalErrors = whoisErrors + rdapErrors;
        if (totalErrors > 0)
        {
            ConsoleOutput.WriteWarning(string.Format(CultureInfo.InvariantCulture,
                "{0} queries failed -- check refresh-results*.json for details", totalErrors));
        }

        return 0;
    }

    private static (int Successes, int Errors) CountResults(RefreshResults results)
    {
        var all = results.Results.Values
            .SelectMany(t => t.Values)
            .SelectMany(s => s.Values)
            .SelectMany(d => d.Values)
            .ToList();

        return (all.Count(r => r.Error == null), all.Count(r => r.Error != null));
    }
}
