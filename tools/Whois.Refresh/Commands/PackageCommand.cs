using System.Globalization;
using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Cli;
using Whois.Templates;
using Whois.Refresh.Domain;

namespace Whois.Refresh.Commands;

public class PackageSettings : CommandSettings
{
    [CommandArgument(0, "<repo-root>")]
    public string RepoRoot { get; set; } = string.Empty;

    [CommandOption("--version <VERSION>")]
    public string Version { get; set; } = string.Empty;

    [CommandOption("--previous-manifest <PATH>")]
    public string? PreviousManifestPath { get; set; }

    [CommandOption("--output <DIR>")]
    public string OutputDir { get; set; } = "./artifacts";
}

public class PackageCommand : AsyncCommand<PackageSettings>
{
    public override Task<int> ExecuteAsync(CommandContext context, PackageSettings settings)
    {
        var result = Run(settings.RepoRoot, settings.Version, settings.PreviousManifestPath, settings.OutputDir);
        return Task.FromResult(result);
    }

    /// <summary>
    /// Core logic extracted for direct testing without Spectre.Cli infrastructure.
    /// </summary>
    internal static int Run(string repoRoot, string version, string? previousManifestPath, string outputDir)
    {
        var isCi = string.Equals(
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.Ordinal);

        // Validate version
        if (!TemplateVersion.TryParse(version, out _))
        {
            ReportError(isCi, $"Invalid CalVer version: {version}");
            return 1;
        }

        // Validate previous manifest path if provided
        if (previousManifestPath != null && !File.Exists(previousManifestPath))
        {
            ReportError(isCi, $"Previous manifest not found: {previousManifestPath}");
            return 1;
        }

        var resourcesDir = Path.Combine(repoRoot, "src", "Whois", "Resources");

        try
        {
            var zipPath = TemplatePackager.CreatePackage(resourcesDir, version, outputDir);

            // Generate changelog if previous manifest provided
            if (previousManifestPath != null)
            {
                var previousJson = File.ReadAllText(previousManifestPath);
                TemplateManifest previousManifest;
                try
                {
                    previousManifest = TemplateManifest.Deserialize(previousJson);
                }
                catch (JsonException ex)
                {
                    ReportWarning(isCi, $"Could not parse previous manifest: {ex.Message}. Skipping changelog.");
                    return 0;
                }
                catch (InvalidOperationException ex)
                {
                    ReportWarning(isCi, $"Could not parse previous manifest: {ex.Message}. Skipping changelog.");
                    return 0;
                }

                var currentJson = File.ReadAllText(Path.Combine(outputDir, "manifest.json"));
                var currentManifest = TemplateManifest.Deserialize(currentJson);

                var changelog = ChangelogGenerator.Generate(currentManifest, previousManifest);
                File.WriteAllText(Path.Combine(outputDir, "changelog.json"), changelog.ToJson());
                File.WriteAllText(Path.Combine(outputDir, "changelog.md"), changelog.ToMarkdown());
            }

            // Summary
            var manifest = TemplateManifest.Deserialize(
                File.ReadAllText(Path.Combine(outputDir, "manifest.json")));

            var templateCountStr = manifest.TemplateCount.ToString(CultureInfo.InvariantCulture);
            if (isCi)
            {
                Console.WriteLine($"::notice::Package created: {templateCountStr} templates, " +
                    $"version {manifest.Version}, content hash {manifest.ContentHash}");
            }
            else
            {
                AnsiConsole.MarkupLine(
                    $"[green]Package created:[/] {templateCountStr} templates, " +
                    $"version {Markup.Escape(manifest.Version)}, content hash {Markup.Escape(manifest.ContentHash)}");
                AnsiConsole.MarkupLine($"[blue]Output:[/] {Markup.Escape(zipPath)}");
            }

            return 0;
        }
        catch (DirectoryNotFoundException ex)
        {
            ReportError(isCi, ex.Message);
            return 1;
        }
        catch (InvalidOperationException ex)
        {
            ReportError(isCi, ex.Message);
            return 1;
        }
    }

    private static void ReportError(bool isCi, string message)
    {
        if (isCi)
            Console.WriteLine($"::error::{message}");
        else
            AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(message)}");
    }

    private static void ReportWarning(bool isCi, string message)
    {
        if (isCi)
            Console.WriteLine($"::warning::{message}");
        else
            AnsiConsole.MarkupLine($"[yellow]Warning:[/] {Markup.Escape(message)}");
    }
}
