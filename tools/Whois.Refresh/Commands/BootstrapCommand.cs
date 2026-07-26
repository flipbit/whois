using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Cli;
using Whois.Refresh.Domain;

namespace Whois.Refresh.Commands;

public class BootstrapSettings : CommandSettings
{
    [CommandArgument(0, "<repo-root>")]
    public string RepoRoot { get; set; } = string.Empty;

    [CommandOption("-o|--output")]
    public string? OutputPath { get; set; }
}

public class BootstrapCommand : AsyncCommand<BootstrapSettings>
{
    public override async Task<int> ExecuteAsync(CommandContext context, BootstrapSettings settings)
    {
        var parsingTestsDir = Path.Combine(settings.RepoRoot, "tests", "Whois.Tests", "Parsing");
        var outputPath = settings.OutputPath
            ?? Path.Combine(settings.RepoRoot, "tools", "Whois.Refresh", "domains.jsonc");

        if (!Directory.Exists(parsingTestsDir))
        {
            AnsiConsole.MarkupLine("[red]Error:[/] Parsing tests directory not found: {0}", parsingTestsDir);
            return 1;
        }

        var testFiles = Directory.GetFiles(parsingTestsDir, "*ParsingTests.cs", SearchOption.AllDirectories);
        AnsiConsole.MarkupLine("Scanning [blue]{0}[/] test files...", testFiles.Length);

        var allEntries = new List<SampleDomainEntry>();

        foreach (var testFile in testFiles)
        {
            var content = await File.ReadAllTextAsync(testFile).ConfigureAwait(false);
            var entries = TestFileParser.ExtractDomains(content);
            allEntries.AddRange(entries);
        }

        AnsiConsole.MarkupLine("Extracted [green]{0}[/] domain entries from tests", allEntries.Count);

        var registry = TestFileParser.BuildRegistry(allEntries);

        AnsiConsole.MarkupLine("Generated registry with [green]{0}[/] servers", registry.Servers.Count);

        var json = SerializeRegistry(registry);
        await File.WriteAllTextAsync(outputPath, json).ConfigureAwait(false);

        AnsiConsole.MarkupLine("Written to [blue]{0}[/]", outputPath);
        return 0;
    }

    private static string SerializeRegistry(DomainRegistryData registry)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        // Build a structure that serializes cleanly
        var serverMap = registry.Servers.ToDictionary(
            kvp => kvp.Key,
            kvp => (object)new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["tld"] = kvp.Value.Tld,
                ["domains"] = kvp.Value.Domains,
            },
            StringComparer.Ordinal);

        var output = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["servers"] = serverMap,
        };

        return JsonSerializer.Serialize(output, options);
    }
}
