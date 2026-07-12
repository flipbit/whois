using Spectre.Console;
using Spectre.Console.Cli;
using WhoisRefresh.Domain;
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Commands;

public class DetectSettings : CommandSettings
{
    [CommandArgument(0, "<repo-root>")]
    public string RepoRoot { get; set; } = string.Empty;
}

public class DetectCommand : AsyncCommand<DetectSettings>
{
    private readonly IDriftReporter _reporter;
    private readonly IFileSystem _fileSystem;

    public DetectCommand(IDriftReporter reporter, IFileSystem fileSystem)
    {
        _reporter = reporter;
        _fileSystem = fileSystem;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, DetectSettings settings)
    {
        var toolDir = Path.Combine(settings.RepoRoot, "tools", "WhoisRefresh");
        var registryPath = Path.Combine(toolDir, "domains.jsonc");
        var resultsPath = Path.Combine(toolDir, "refresh-results.json");

        if (!_fileSystem.FileExists(resultsPath))
        {
            AnsiConsole.MarkupLine("[red]Error:[/] No refresh-results.json found. Run 'refresh' first.");
            return 1;
        }

        var registry = await DomainRegistry.LoadFromFileAsync(registryPath);
        var currentJson = await _fileSystem.ReadAllTextAsync(resultsPath);
        var current = RefreshResults.Deserialize(currentJson);

        var detector = new DriftDetector(_reporter, _fileSystem);
        var entries = await detector.DetectAsync(current, registry, settings.RepoRoot, "tools/WhoisRefresh", CancellationToken.None);

        var isCi = Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";
        OutputResults(entries, isCi);

        if (entries.Count > 0)
        {
            var jsonReport = DriftReportGenerator.ToJson(entries);
            var mdReport = DriftReportGenerator.ToMarkdown(entries);
            await _fileSystem.WriteAllTextAsync(Path.Combine(toolDir, "drift-report.json"), jsonReport);
            await _fileSystem.WriteAllTextAsync(Path.Combine(toolDir, "drift-report.md"), mdReport);
        }

        return entries.Any(e => e.Severity == DriftSeverity.Breakage) ? 1 : 0;
    }

    private static void OutputResults(List<DriftEntry> entries, bool isCi)
    {
        if (entries.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]No drift detected.[/]");
            return;
        }

        foreach (var entry in entries)
        {
            if (isCi)
            {
                var annotation = entry.Severity switch
                {
                    DriftSeverity.Breakage => "::error::",
                    DriftSeverity.Warning => "::warning::",
                    _ => "::notice::"
                };
                Console.WriteLine($"{annotation}{entry.Domain} ({entry.Server}): {entry.Details}");
            }
            else
            {
                var color = entry.Severity switch
                {
                    DriftSeverity.Breakage => "red",
                    DriftSeverity.Warning => "yellow",
                    DriftSeverity.Drift => "yellow",
                    _ => "blue"
                };
                AnsiConsole.MarkupLine($"[{color}]{entry.Severity}[/] {Markup.Escape(entry.Domain)} ({Markup.Escape(entry.Server)}): {Markup.Escape(entry.Details)}");
            }
        }
    }
}
