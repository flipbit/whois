using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Cli;
using Whois.Refresh.Domain;
using Whois.Servers;

namespace Whois.Refresh.Commands;

public class BootstrapSettings : CommandSettings
{
    [CommandArgument(0, "<repo-root>")]
    public string RepoRoot { get; set; } = string.Empty;

    [CommandOption("-o|--output")]
    public string? OutputPath { get; set; }

    [CommandOption("--protocol")]
    public string? Protocol { get; set; }
}

public class BootstrapCommand : AsyncCommand<BootstrapSettings>
{
    private static readonly string IanaRdapBootstrapUrl = new WhoisOptions().RdapBootstrapUrl;

    private readonly HttpClient _httpClient;

    public BootstrapCommand(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public override async Task<int> ExecuteAsync(CommandContext context, BootstrapSettings settings)
    {
        if (Enum.TryParse<LookupProtocol>(settings.Protocol, ignoreCase: true, out var protocol)
            && protocol == LookupProtocol.Rdap)
        {
            return await SeedRdapAsync(settings).ConfigureAwait(false);
        }

        return await SeedWhoisAsync(settings).ConfigureAwait(false);
    }

    private async Task<int> SeedRdapAsync(BootstrapSettings settings)
    {
        var toolDir = Path.Combine(settings.RepoRoot, "tools", "Whois.Refresh");
        var whoisRegistryPath = Path.Combine(toolDir, "domains-whois.jsonc");
        var outputPath = settings.OutputPath
            ?? Path.Combine(toolDir, "domains-rdap.jsonc");

        // Fetch IANA RDAP bootstrap data
        AnsiConsole.MarkupLine("Fetching IANA RDAP bootstrap data...");
        var rdapJson = await _httpClient.GetStringAsync(
            IanaRdapBootstrapUrl).ConfigureAwait(false);
        var rdapEndpoints = BootstrapRegistry.ParseBootstrapJson(rdapJson);
        AnsiConsole.MarkupLine("Found [green]{0}[/] TLDs with RDAP endpoints", rdapEndpoints.Count);

        // Load existing WHOIS domains for cross-reference
        DomainRegistryData? whoisRegistry = null;
        if (File.Exists(whoisRegistryPath))
        {
            whoisRegistry = await DomainRegistry.LoadFromFileAsync(whoisRegistryPath)
                .ConfigureAwait(false);
            AnsiConsole.MarkupLine("Loaded [blue]{0}[/] WHOIS servers for cross-reference",
                whoisRegistry.Servers.Count);
        }

        // Build RDAP registry by cross-referencing
        var servers = new Dictionary<string, object>(StringComparer.Ordinal);
        var tldsCovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // First pass: reuse domains from WHOIS registry
        if (whoisRegistry != null)
        {
            foreach (var (serverName, server) in whoisRegistry.Servers)
            {
                var tld = server.Tld;
                if (tldsCovered.Contains(tld)) continue;
                if (!rdapEndpoints.TryGetValue(tld, out var rdapBaseUrl)) continue;

                var foundDomains = server.Domains
                    .Where(kvp => string.Equals(kvp.Key, "found", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(kvp => kvp.Value)
                    .Take(1)
                    .ToList();

                if (foundDomains.Count == 0) continue;

                var rdapHostname = new Uri(rdapBaseUrl).Host;
                servers[rdapHostname] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["tld"] = tld,
                    ["rdapBaseUrl"] = rdapBaseUrl,
                    ["domains"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["found"] = foundDomains,
                    },
                };
                tldsCovered.Add(tld);
            }
        }

        // Second pass: fill gaps with well-known domains
        foreach (var (tld, rdapBaseUrl) in rdapEndpoints)
        {
            if (tldsCovered.Contains(tld)) continue;

            var rdapHostname = new Uri(rdapBaseUrl).Host;
            // Skip if we already have this RDAP host from a different TLD
            if (servers.ContainsKey(rdapHostname)) continue;

            servers[rdapHostname] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["tld"] = tld,
                ["rdapBaseUrl"] = rdapBaseUrl,
                ["domains"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["found"] = new List<string> { $"google.{tld}" },
                },
            };
            tldsCovered.Add(tld);
        }

        var output = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["servers"] = servers,
        };

        var json = JsonSerializer.Serialize(output, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        });

        await File.WriteAllTextAsync(outputPath, json).ConfigureAwait(false);

        AnsiConsole.MarkupLine("Written [green]{0}[/] RDAP servers to [blue]{1}[/]",
            servers.Count, outputPath);
        return 0;
    }

    private static async Task<int> SeedWhoisAsync(BootstrapSettings settings)
    {
        var parsingTestsDir = Path.Combine(settings.RepoRoot, "tests", "Whois.Tests", "Parsing");
        var outputPath = settings.OutputPath
            ?? Path.Combine(settings.RepoRoot, "tools", "Whois.Refresh", "domains-whois.jsonc");

        if (!Directory.Exists(parsingTestsDir))
        {
            AnsiConsole.MarkupLine("[red]Error:[/] Parsing tests directory not found: {0}",
                parsingTestsDir);
            return 1;
        }

        var testFiles = Directory.GetFiles(parsingTestsDir, "*ParsingTests.cs",
            SearchOption.AllDirectories);
        AnsiConsole.MarkupLine("Scanning [blue]{0}[/] test files...", testFiles.Length);

        var allEntries = new List<SampleDomainEntry>();

        foreach (var testFile in testFiles)
        {
            var content = await File.ReadAllTextAsync(testFile).ConfigureAwait(false);
            var entries = TestFileParser.ExtractDomains(content);
            allEntries.AddRange(entries);
        }

        AnsiConsole.MarkupLine("Extracted [green]{0}[/] domain entries from tests",
            allEntries.Count);

        var registry = TestFileParser.BuildRegistry(allEntries);

        AnsiConsole.MarkupLine("Generated registry with [green]{0}[/] servers",
            registry.Servers.Count);

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
