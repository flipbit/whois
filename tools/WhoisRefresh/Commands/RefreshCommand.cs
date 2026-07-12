using System.Globalization;
using Spectre.Console.Cli;
using Whois.Net;
using WhoisRefresh.Domain;
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Commands;

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
}

public class RefreshCommand : AsyncCommand<RefreshSettings>
{
    private readonly ITcpReader _tcpReader;
    private readonly IFileSystem _fileSystem;

    public RefreshCommand(ITcpReader tcpReader, IFileSystem fileSystem)
    {
        _tcpReader = tcpReader;
        _fileSystem = fileSystem;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, RefreshSettings settings)
    {
        var toolDir = Path.Combine(settings.RepoRoot, "tools", "WhoisRefresh");
        var registryPath = Path.Combine(toolDir, "domains.jsonc");
        var resultsPath = Path.Combine(toolDir, "refresh-results.json");
        var samplesPath = Path.Combine(settings.RepoRoot, "tests", "Whois.Tests", "Samples");

        if (!File.Exists(registryPath))
        {
            ConsoleOutput.WriteError($"domains.jsonc not found at {registryPath}");
            return 1;
        }

        var registry = await DomainRegistry.LoadFromFileAsync(registryPath).ConfigureAwait(false);

        var queryableServers = registry.Servers.Count(s => !s.Value.IsStatic);
        var totalDomains = registry.Servers
            .Where(s => !s.Value.IsStatic)
            .SelectMany(s => s.Value.Domains.Values)
            .Sum(d => d.Count);

        ConsoleOutput.WriteInfo(string.Format(CultureInfo.InvariantCulture, "Querying {0} domains across {1} servers...", totalDomains, queryableServers));

        var options = new RefreshEngineOptions(
            SamplesBasePath: samplesPath,
            DelayBetweenQueries: TimeSpan.FromMilliseconds(settings.DelayMs),
            QueryTimeoutSeconds: settings.TimeoutSeconds,
            MaxResponseBytes: settings.MaxResponseBytes);

        var engine = new RefreshEngine(_tcpReader, _fileSystem);
        var results = await engine.RunAsync(registry, options, CancellationToken.None).ConfigureAwait(false);

        // Prune removed domains
        results.Prune(registry);

        // Write results
        var json = RefreshResults.Serialize(results);
        await _fileSystem.WriteAllTextAsync(resultsPath, json).ConfigureAwait(false);

        // Summary
        var errors = results.Results.Values
            .SelectMany(t => t.Values)
            .SelectMany(s => s.Values)
            .SelectMany(d => d.Values)
            .Count(r => r.Error != null);

        var successes = results.Results.Values
            .SelectMany(t => t.Values)
            .SelectMany(s => s.Values)
            .SelectMany(d => d.Values)
            .Count(r => r.Error == null);

        ConsoleOutput.WriteSuccess(string.Format(CultureInfo.InvariantCulture, "Refresh complete: {0} succeeded, {1} failed", successes, errors));

        if (errors > 0)
        {
            ConsoleOutput.WriteWarning(string.Format(CultureInfo.InvariantCulture, "{0} queries failed — check refresh-results.json for details", errors));
        }

        return 0;
    }
}
