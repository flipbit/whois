# Refresh Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a .NET console tool that queries live WHOIS servers, saves responses, detects parsing drift, and manages a rolling PR for breakages.

**Architecture:** Single Spectre.Cli console app at `tools/WhoisRefresh/` with three commands (`refresh`, `detect`, `bootstrap`). Uses the main Whois library's `WhoisParser` and `ITcpReader` for parsing and network. File I/O and PR management behind interfaces for testability.

**Tech Stack:** .NET 10, Spectre.Console/Spectre.Cli, System.Text.Json (JSONC), xUnit + NSubstitute

## Global Constraints

- Target framework: `net10.0` (tool only, not a library)
- `TreatWarningsAsErrors=true`, `Nullable=enable` (inherited from Directory.Build.props)
- Central Package Management via `Directory.Packages.props`
- All tests use xUnit + NSubstitute
- Follow TDD: failing test → minimal implementation → verify pass → commit
- No mocking of `WhoisParser` internals — use real parser with test fixture responses
- Domain names in `domains.jsonc` must never contain `/`, `\`, or `..`

---

### Task 1: Project Scaffolding + Domain Registry

**Files:**
- Create: `tools/WhoisRefresh/WhoisRefresh.csproj`
- Create: `tools/WhoisRefresh/Program.cs`
- Create: `tools/WhoisRefresh/Domain/DomainRegistry.cs`
- Create: `tools/WhoisRefresh/Domain/ServerEntry.cs`
- Create: `tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj`
- Create: `tests/WhoisRefresh.Tests/DomainRegistryTests.cs`
- Modify: `Whois.sln` (add both projects)
- Modify: `Directory.Packages.props` (add Spectre.Console packages)

**Interfaces:**
- Produces: `DomainRegistry.LoadAsync(string path)` → `DomainRegistryData`
- Produces: `ServerEntry` record: `{ Tld, IsStatic, RateGroup, Domains (Dictionary<string, List<string>>) }`
- Produces: `DomainRegistryData` record: `{ Servers (Dictionary<string, ServerEntry>) }`

- [ ] **Step 1: Create project files**

`tools/WhoisRefresh/WhoisRefresh.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>WhoisRefresh</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Spectre.Console" />
    <PackageReference Include="Spectre.Console.Cli" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\Whois\Whois.csproj" />
  </ItemGroup>
</Project>
```

`tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RootNamespace>WhoisRefresh.Tests</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio" />
    <PackageReference Include="NSubstitute" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\tools\WhoisRefresh\WhoisRefresh.csproj" />
  </ItemGroup>
</Project>
```

`tools/WhoisRefresh/Program.cs`:
```csharp
using Spectre.Console.Cli;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
});

return await app.RunAsync(args);
```

- [ ] **Step 2: Add package versions to Directory.Packages.props**

Add under the `<!-- Console app -->` section:
```xml
<PackageVersion Include="Spectre.Console" Version="0.50.0" />
<PackageVersion Include="Spectre.Console.Cli" Version="0.50.0" />
```

- [ ] **Step 3: Add projects to solution**

Run:
```bash
dotnet sln Whois.sln add tools/WhoisRefresh/WhoisRefresh.csproj --solution-folder tools
dotnet sln Whois.sln add tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --solution-folder tests
```

- [ ] **Step 4: Verify build succeeds**

Run: `dotnet build Whois.sln`
Expected: Build succeeded with 0 errors.

- [ ] **Step 5: Write failing tests for DomainRegistry**

`tests/WhoisRefresh.Tests/DomainRegistryTests.cs`:
```csharp
using WhoisRefresh.Domain;

namespace WhoisRefresh.Tests;

public class DomainRegistryTests
{
    [Fact]
    public async Task LoadAsync_ValidJsonc_ParsesServers()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  // UK registry
                  "tld": "uk",
                  "domains": {
                    "found": ["google.co.uk", "bbc.co.uk"],
                    "not-found": ["u34jedzcq.co.uk"]
                  }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.Single(registry.Servers);
        var server = registry.Servers["whois.nic.uk"];
        Assert.Equal("uk", server.Tld);
        Assert.False(server.IsStatic);
        Assert.Null(server.RateGroup);
        Assert.Equal(2, server.Domains["found"].Count);
        Assert.Contains("google.co.uk", server.Domains["found"]);
        Assert.Single(server.Domains["not-found"]);
    }

    [Fact]
    public async Task LoadAsync_StaticServer_ParsesFlag()
    {
        var jsonc = """
            {
              "servers": {
                "whois.denic.de": {
                  "tld": "de",
                  "static": true,
                  "domains": {
                    "found": ["google.de"]
                  }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.True(registry.Servers["whois.denic.de"].IsStatic);
    }

    [Fact]
    public async Task LoadAsync_RateGroup_ParsesGroup()
    {
        var jsonc = """
            {
              "servers": {
                "whois.verisign-grs.com": {
                  "tld": "com",
                  "rateGroup": "verisign",
                  "domains": { "found": ["google.com"] }
                },
                "ccwhois.verisign-grs.com": {
                  "tld": "cc",
                  "rateGroup": "verisign",
                  "domains": { "found": ["example.cc"] }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.Equal("verisign", registry.Servers["whois.verisign-grs.com"].RateGroup);
        Assert.Equal("verisign", registry.Servers["ccwhois.verisign-grs.com"].RateGroup);
    }

    [Fact]
    public async Task LoadAsync_DomainWithPathSeparator_ThrowsValidation()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": { "found": ["../etc/passwd"] }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("../etc/passwd", ex.Message);
    }

    [Fact]
    public async Task LoadAsync_DomainWithBackslash_ThrowsValidation()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": { "found": ["foo\\bar.uk"] }
                }
              }
            }
            """;

        var ex = await Assert.ThrowsAsync<DomainRegistryValidationException>(
            () => DomainRegistry.LoadAsync(jsonc));
        Assert.Contains("foo\\bar.uk", ex.Message);
    }

    [Fact]
    public async Task LoadAsync_TrailingCommas_Accepted()
    {
        var jsonc = """
            {
              "servers": {
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": {
                    "found": ["google.co.uk",],
                  },
                },
              },
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);

        Assert.Single(registry.Servers);
    }

    [Fact]
    public async Task GetRateGroups_GroupsServersCorrectly()
    {
        var jsonc = """
            {
              "servers": {
                "whois.verisign-grs.com": {
                  "tld": "com",
                  "rateGroup": "verisign",
                  "domains": { "found": ["google.com"] }
                },
                "ccwhois.verisign-grs.com": {
                  "tld": "cc",
                  "rateGroup": "verisign",
                  "domains": { "found": ["example.cc"] }
                },
                "whois.nic.uk": {
                  "tld": "uk",
                  "domains": { "found": ["google.co.uk"] }
                }
              }
            }
            """;

        var registry = await DomainRegistry.LoadAsync(jsonc);
        var groups = registry.GetRateGroups();

        // "verisign" group has 2 servers, "whois.nic.uk" is its own group
        Assert.Equal(2, groups.Count);
        var verisignGroup = groups.First(g => g.Key == "verisign");
        Assert.Equal(2, verisignGroup.Count());
        var ukGroup = groups.First(g => g.Key == "whois.nic.uk");
        Assert.Single(ukGroup);
    }
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj`
Expected: FAIL — types `DomainRegistry`, `ServerEntry`, `DomainRegistryData`, `DomainRegistryValidationException` don't exist.

- [ ] **Step 7: Implement DomainRegistry**

`tools/WhoisRefresh/Domain/ServerEntry.cs`:
```csharp
namespace WhoisRefresh.Domain;

public record ServerEntry(
    string Tld,
    bool IsStatic,
    string? RateGroup,
    Dictionary<string, List<string>> Domains);
```

`tools/WhoisRefresh/Domain/DomainRegistry.cs`:
```csharp
using System.Text.Json;

namespace WhoisRefresh.Domain;

public record DomainRegistryData(Dictionary<string, ServerEntry> Servers)
{
    /// <summary>
    /// Groups servers by rate group. Servers without a rateGroup are each their own group
    /// (keyed by server name).
    /// </summary>
    public ILookup<string, KeyValuePair<string, ServerEntry>> GetRateGroups()
    {
        return Servers
            .Where(s => !s.Value.IsStatic)
            .ToLookup(s => s.Value.RateGroup ?? s.Key);
    }
}

public class DomainRegistryValidationException : Exception
{
    public DomainRegistryValidationException(string message) : base(message) { }
}

public static class DomainRegistry
{
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static async Task<DomainRegistryData> LoadAsync(string jsonc)
    {
        await Task.CompletedTask; // Sync parse, async signature for file-based overload later

        using var doc = JsonDocument.Parse(jsonc, JsonOptions);
        var root = doc.RootElement;
        var serversElement = root.GetProperty("servers");

        var servers = new Dictionary<string, ServerEntry>();

        foreach (var serverProp in serversElement.EnumerateObject())
        {
            var serverName = serverProp.Name;
            var serverObj = serverProp.Value;

            var tld = serverObj.GetProperty("tld").GetString()!;
            var isStatic = serverObj.TryGetProperty("static", out var staticProp) && staticProp.GetBoolean();
            var rateGroup = serverObj.TryGetProperty("rateGroup", out var rgProp) && rgProp.ValueKind != JsonValueKind.Null
                ? rgProp.GetString()
                : null;

            var domains = new Dictionary<string, List<string>>();
            var domainsObj = serverObj.GetProperty("domains");

            foreach (var statusProp in domainsObj.EnumerateObject())
            {
                var status = statusProp.Name;
                var domainList = new List<string>();

                foreach (var domainElement in statusProp.Value.EnumerateArray())
                {
                    var domain = domainElement.GetString()!;
                    ValidateDomainName(domain);
                    domainList.Add(domain);
                }

                domains[status] = domainList;
            }

            servers[serverName] = new ServerEntry(tld, isStatic, rateGroup, domains);
        }

        return new DomainRegistryData(servers);
    }

    public static async Task<DomainRegistryData> LoadFromFileAsync(string path)
    {
        var content = await File.ReadAllTextAsync(path);
        return await LoadAsync(content);
    }

    private static void ValidateDomainName(string domain)
    {
        if (domain.Contains('/') || domain.Contains('\\') || domain.Contains(".."))
        {
            throw new DomainRegistryValidationException(
                $"Invalid domain name '{domain}': contains path separator or traversal sequence");
        }
    }
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj`
Expected: All 7 tests PASS.

- [ ] **Step 9: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/ Whois.sln Directory.Packages.props
git commit -m "feat(refresh): scaffold WhoisRefresh project with DomainRegistry loading and validation"
```

---

### Task 2: Bootstrap Command

**Files:**
- Create: `tools/WhoisRefresh/Commands/BootstrapCommand.cs`
- Create: `tools/WhoisRefresh/Domain/TestFileParser.cs`
- Create: `tests/WhoisRefresh.Tests/BootstrapCommandTests.cs`
- Modify: `tools/WhoisRefresh/Program.cs` (register command)

**Interfaces:**
- Consumes: `DomainRegistryData`, `ServerEntry` from Task 1
- Produces: `TestFileParser.ExtractDomains(string testFileContent)` → `List<SampleDomainEntry>`
- Produces: `SampleDomainEntry` record: `{ Server, Tld, Status, Filename, DomainName }`

- [ ] **Step 1: Write failing tests for TestFileParser**

`tests/WhoisRefresh.Tests/BootstrapCommandTests.cs`:
```csharp
using WhoisRefresh.Domain;

namespace WhoisRefresh.Tests;

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
            e.Server == "whois.nic.uk" && e.Tld == "uk" && e.Status == "found" &&
            e.DomainName == "netbenefit.co.uk");
        Assert.Contains(entries, e =>
            e.Server == "whois.nic.uk" && e.Tld == "uk" && e.Status == "not-found" &&
            e.DomainName == "u34jedzcq.co.uk");
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
        Assert.Contains(entries, e => e.DomainName == "netbenefit.co.uk");
        Assert.Contains(entries, e => e.DomainName == "bedandbreakfastsearcher.co.uk");
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

        // Both entries are returned — deduplication happens at registry generation level
        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public void BuildRegistry_GroupsByServerAndStatus_DeduplicatesDomains()
    {
        var entries = new List<SampleDomainEntry>
        {
            new("whois.nic.uk", "uk", "found", "found.txt", "netbenefit.co.uk"),
            new("whois.nic.uk", "uk", "found", "found_other.txt", "netbenefit.co.uk"),
            new("whois.nic.uk", "uk", "found", "found_bbc.txt", "bbc.co.uk"),
            new("whois.nic.uk", "uk", "not-found", "not_found.txt", "u34jedzcq.co.uk"),
        };

        var registry = TestFileParser.BuildRegistry(entries);

        var server = registry.Servers["whois.nic.uk"];
        Assert.Equal("uk", server.Tld);
        Assert.Equal(2, server.Domains["found"].Count); // deduplicated
        Assert.Contains("netbenefit.co.uk", server.Domains["found"]);
        Assert.Contains("bbc.co.uk", server.Domains["found"]);
        Assert.Single(server.Domains["not-found"]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "BootstrapCommandTests"`
Expected: FAIL — `TestFileParser` and `SampleDomainEntry` don't exist.

- [ ] **Step 3: Implement TestFileParser**

`tools/WhoisRefresh/Domain/TestFileParser.cs`:
```csharp
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

    public static List<SampleDomainEntry> ExtractDomains(string testFileContent)
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

    public static DomainRegistryData BuildRegistry(List<SampleDomainEntry> entries)
    {
        var servers = new Dictionary<string, ServerEntry>();

        var grouped = entries.GroupBy(e => e.Server);

        foreach (var serverGroup in grouped)
        {
            var serverName = serverGroup.Key;
            var tld = serverGroup.First().Tld;
            var domains = new Dictionary<string, List<string>>();

            foreach (var statusGroup in serverGroup.GroupBy(e => e.Status))
            {
                var uniqueDomains = statusGroup
                    .Select(e => e.DomainName)
                    .Distinct()
                    .OrderBy(d => d)
                    .ToList();
                domains[statusGroup.Key] = uniqueDomains;
            }

            servers[serverName] = new ServerEntry(tld, IsStatic: false, RateGroup: null, domains);
        }

        return new DomainRegistryData(servers);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "BootstrapCommandTests"`
Expected: All 5 tests PASS.

- [ ] **Step 5: Implement BootstrapCommand**

`tools/WhoisRefresh/Commands/BootstrapCommand.cs`:
```csharp
using System.Text.Json;
using Spectre.Console;
using Spectre.Console.Cli;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Commands;

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
            ?? Path.Combine(settings.RepoRoot, "tools", "WhoisRefresh", "domains.jsonc");

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
            var content = await File.ReadAllTextAsync(testFile);
            var entries = TestFileParser.ExtractDomains(content);
            allEntries.AddRange(entries);
        }

        AnsiConsole.MarkupLine("Extracted [green]{0}[/] domain entries from tests", allEntries.Count);

        var registry = TestFileParser.BuildRegistry(allEntries);

        AnsiConsole.MarkupLine("Generated registry with [green]{0}[/] servers", registry.Servers.Count);

        var json = SerializeRegistry(registry);
        await File.WriteAllTextAsync(outputPath, json);

        AnsiConsole.MarkupLine("Written to [blue]{0}[/]", outputPath);
        return 0;
    }

    private static string SerializeRegistry(DomainRegistryData registry)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        // Build a structure that serializes cleanly
        var output = new Dictionary<string, object>
        {
            ["servers"] = registry.Servers.ToDictionary(
                kvp => kvp.Key,
                kvp => new Dictionary<string, object?>
                {
                    ["tld"] = kvp.Value.Tld,
                    ["domains"] = kvp.Value.Domains
                })
        };

        return JsonSerializer.Serialize(output, options);
    }
}
```

- [ ] **Step 6: Register command in Program.cs**

Update `tools/WhoisRefresh/Program.cs`:
```csharp
using Spectre.Console.Cli;
using WhoisRefresh.Commands;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
});

return await app.RunAsync(args);
```

- [ ] **Step 7: Build and verify**

Run: `dotnet build Whois.sln`
Expected: Build succeeded.

- [ ] **Step 8: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/
git commit -m "feat(refresh): add bootstrap command to generate domains.jsonc from tests"
```

---

### Task 3: File System Abstraction + Refresh Result Models

**Files:**
- Create: `tools/WhoisRefresh/Infrastructure/IFileSystem.cs`
- Create: `tools/WhoisRefresh/Infrastructure/PhysicalFileSystem.cs`
- Create: `tools/WhoisRefresh/Domain/RefreshResult.cs`
- Create: `tests/WhoisRefresh.Tests/RefreshResultTests.cs`

**Interfaces:**
- Produces: `IFileSystem` with `ReadAllTextAsync`, `WriteAllTextAsync`, `FileExists`, `DirectoryExists`, `CreateDirectory`
- Produces: `RefreshResults` record: `{ Version (DateTimeOffset), Results (nested dict: server → tld → status → domain → DomainResult) }`
- Produces: `DomainResult` record: `{ Timestamp, MatchedTemplate, ExtractedFields (List<string>), Error (QueryError?) }`
- Produces: `QueryError` record: `{ Type (QueryErrorType enum), Message, Detail }`
- Produces: `RefreshResults.SerializeAsync()` / `DeserializeAsync()`

- [ ] **Step 1: Write failing tests for RefreshResult serialization**

`tests/WhoisRefresh.Tests/RefreshResultTests.cs`:
```csharp
using WhoisRefresh.Domain;

namespace WhoisRefresh.Tests;

public class RefreshResultTests
{
    [Fact]
    public void Serialize_RoundTrips_Successfully()
    {
        var results = new RefreshResults
        {
            Version = new DateTimeOffset(2026, 7, 12, 2, 0, 0, TimeSpan.Zero),
            Results = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, DomainResult>>>>
            {
                ["whois.nic.uk"] = new()
                {
                    ["uk"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.co.uk"] = new DomainResult
                            {
                                Timestamp = new DateTimeOffset(2026, 7, 12, 2, 1, 15, TimeSpan.Zero),
                                MatchedTemplate = "whois.nic.uk/uk/found/01",
                                ExtractedFields = ["DomainName", "Registrar", "CreatedDate"],
                                Error = null
                            }
                        }
                    }
                }
            }
        };

        var json = RefreshResults.Serialize(results);
        var deserialized = RefreshResults.Deserialize(json);

        Assert.Equal(results.Version, deserialized.Version);
        var domainResult = deserialized.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.Equal("whois.nic.uk/uk/found/01", domainResult.MatchedTemplate);
        Assert.Equal(3, domainResult.ExtractedFields.Count);
        Assert.Null(domainResult.Error);
    }

    [Fact]
    public void Serialize_WithError_RoundTrips()
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, DomainResult>>>>
            {
                ["whois.denic.de"] = new()
                {
                    ["de"] = new()
                    {
                        ["found"] = new()
                        {
                            ["google.de"] = new DomainResult
                            {
                                Timestamp = DateTimeOffset.UtcNow,
                                MatchedTemplate = null,
                                ExtractedFields = [],
                                Error = new QueryError
                                {
                                    Type = QueryErrorType.ConnectionRefused,
                                    Message = "Connection refused",
                                    Detail = "whois.denic.de:43"
                                }
                            }
                        }
                    }
                }
            }
        };

        var json = RefreshResults.Serialize(results);
        var deserialized = RefreshResults.Deserialize(json);

        var error = deserialized.Results["whois.denic.de"]["de"]["found"]["google.de"].Error;
        Assert.NotNull(error);
        Assert.Equal(QueryErrorType.ConnectionRefused, error.Type);
        Assert.Equal("Connection refused", error.Message);
    }

    [Fact]
    public void Prune_RemovesDomains_NotInRegistry()
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, DomainResult>>>>
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
                            },
                            ["removed-domain.co.uk"] = new DomainResult
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

        results.Prune(registry);

        Assert.Single(results.Results["whois.nic.uk"]["uk"]["found"]);
        Assert.True(results.Results["whois.nic.uk"]["uk"]["found"].ContainsKey("google.co.uk"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "RefreshResultTests"`
Expected: FAIL — types don't exist.

- [ ] **Step 3: Implement IFileSystem**

`tools/WhoisRefresh/Infrastructure/IFileSystem.cs`:
```csharp
namespace WhoisRefresh.Infrastructure;

public interface IFileSystem
{
    Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default);
    Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default);
    bool FileExists(string path);
    bool DirectoryExists(string path);
    void CreateDirectory(string path);
}
```

`tools/WhoisRefresh/Infrastructure/PhysicalFileSystem.cs`:
```csharp
namespace WhoisRefresh.Infrastructure;

public class PhysicalFileSystem : IFileSystem
{
    public Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default)
        => File.ReadAllTextAsync(path, cancellationToken);

    public Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default)
        => File.WriteAllTextAsync(path, content, cancellationToken);

    public bool FileExists(string path) => File.Exists(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
}
```

- [ ] **Step 4: Implement RefreshResult models**

`tools/WhoisRefresh/Domain/RefreshResult.cs`:
```csharp
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WhoisRefresh.Domain;

public enum QueryErrorType
{
    Timeout,
    ConnectionRefused,
    RateLimited,
    AccessDenied,
    ParseFailure,
    ResponseTooLarge,
    Unknown
}

public class QueryError
{
    public QueryErrorType Type { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Detail { get; set; }
}

public class DomainResult
{
    public DateTimeOffset Timestamp { get; set; }
    public string? MatchedTemplate { get; set; }
    public List<string> ExtractedFields { get; set; } = [];
    public QueryError? Error { get; set; }
}

public class RefreshResults
{
    public DateTimeOffset Version { get; set; }

    public Dictionary<string, Dictionary<string, Dictionary<string, Dictionary<string, DomainResult>>>> Results { get; set; } = new();

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static string Serialize(RefreshResults results)
    {
        return JsonSerializer.Serialize(results, SerializerOptions);
    }

    public static RefreshResults Deserialize(string json)
    {
        return JsonSerializer.Deserialize<RefreshResults>(json, SerializerOptions)
            ?? throw new InvalidOperationException("Failed to deserialize refresh results");
    }

    /// <summary>
    /// Removes entries for domains not present in the registry.
    /// </summary>
    public void Prune(DomainRegistryData registry)
    {
        var serversToRemove = new List<string>();

        foreach (var (serverName, tlds) in Results)
        {
            if (!registry.Servers.ContainsKey(serverName))
            {
                serversToRemove.Add(serverName);
                continue;
            }

            var registryServer = registry.Servers[serverName];

            foreach (var (tld, statuses) in tlds)
            {
                foreach (var (status, domains) in statuses)
                {
                    var registryDomains = registryServer.Domains.GetValueOrDefault(status) ?? [];
                    var domainsToRemove = domains.Keys
                        .Where(d => !registryDomains.Contains(d))
                        .ToList();

                    foreach (var domain in domainsToRemove)
                    {
                        domains.Remove(domain);
                    }
                }
            }
        }

        foreach (var server in serversToRemove)
        {
            Results.Remove(server);
        }
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "RefreshResultTests"`
Expected: All 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/
git commit -m "feat(refresh): add IFileSystem abstraction and RefreshResult models with serialization"
```

---

### Task 4: Refresh Engine (Query + Save Logic)

**Files:**
- Create: `tools/WhoisRefresh/Domain/RefreshEngine.cs`
- Create: `tests/WhoisRefresh.Tests/RefreshEngineTests.cs`

**Interfaces:**
- Consumes: `DomainRegistryData`, `ServerEntry` from Task 1
- Consumes: `IFileSystem` from Task 3
- Consumes: `RefreshResults`, `DomainResult`, `QueryError`, `QueryErrorType` from Task 3
- Consumes: `ITcpReader` from `Whois.Net` namespace (main library)
- Consumes: `WhoisParser` from `Whois.Parsers` namespace (main library)
- Produces: `RefreshEngine.RunAsync(DomainRegistryData, RefreshEngineOptions, CancellationToken)` → `RefreshResults`
- Produces: `RefreshEngineOptions` record: `{ SamplesBasePath, DelayBetweenQueries (TimeSpan), QueryTimeout (int seconds), MaxResponseBytes (int) }`

- [ ] **Step 1: Write failing tests for RefreshEngine**

`tests/WhoisRefresh.Tests/RefreshEngineTests.cs`:
```csharp
using System.Text;
using NSubstitute;
using Whois.Net;
using Whois.Parsers;
using WhoisRefresh.Domain;
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Tests;

public class RefreshEngineTests
{
    private readonly ITcpReader _tcpReader = Substitute.For<ITcpReader>();
    private readonly IFileSystem _fileSystem = Substitute.For<IFileSystem>();
    private readonly RefreshEngineOptions _options = new(
        SamplesBasePath: "/repo/tests/Whois.Tests/Samples",
        DelayBetweenQueries: TimeSpan.Zero, // no delay in tests
        QueryTimeoutSeconds: 30,
        MaxResponseBytes: 65536);

    private RefreshEngine CreateEngine() => new(_tcpReader, _fileSystem);

    [Fact]
    public async Task RunAsync_SingleDomain_QueriesAndSavesResponse()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        var whoisResponse = "Domain Name: google.co.uk\r\nRegistrar: Test Registrar\r\n";
        _tcpReader.Read("whois.nic.uk", 43, "google.co.uk\r\n", Arg.Any<Encoding>(), 30, Arg.Any<CancellationToken>())
            .Returns(whoisResponse);

        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        // Verify response was saved
        await _fileSystem.Received(1).WriteAllTextAsync(
            "/repo/tests/Whois.Tests/Samples/whois.nic.uk/uk/found/google.co.uk.txt",
            whoisResponse,
            Arg.Any<CancellationToken>());

        // Verify result recorded
        var domainResult = results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.NotNull(domainResult);
        Assert.Null(domainResult.Error);
    }

    [Fact]
    public async Task RunAsync_StaticServer_SkipsQuery()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.denic.de"] = new("de", IsStatic: true, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.de"]
            })
        });

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        await _tcpReader.DidNotReceive().Read(
            Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
            Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>());

        Assert.Empty(results.Results);
    }

    [Fact]
    public async Task RunAsync_QueryTimeout_RecordsError()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new OperationCanceledException("Timeout"));

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        var domainResult = results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.NotNull(domainResult.Error);
        Assert.Equal(QueryErrorType.Timeout, domainResult.Error.Type);
    }

    [Fact]
    public async Task RunAsync_ResponseExceedsMaxSize_TruncatesAndRecordsError()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        var options = _options with { MaxResponseBytes: 100 };
        var largeResponse = new string('x', 200);

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(largeResponse);

        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options with { MaxResponseBytes = 100 }, CancellationToken.None);

        var domainResult = results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"];
        Assert.NotNull(domainResult.Error);
        Assert.Equal(QueryErrorType.ResponseTooLarge, domainResult.Error.Type);
    }

    [Fact]
    public async Task RunAsync_PartialFailure_CollectsAllResults()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk", "bbc.co.uk"]
            })
        });

        _tcpReader.Read("whois.nic.uk", 43, "google.co.uk\r\n", Arg.Any<Encoding>(), 30, Arg.Any<CancellationToken>())
            .Returns("Domain Name: google.co.uk\r\n");
        _tcpReader.Read("whois.nic.uk", 43, "bbc.co.uk\r\n", Arg.Any<Encoding>(), 30, Arg.Any<CancellationToken>())
            .ThrowsAsync(new OperationCanceledException("Timeout"));

        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        Assert.Equal(2, results.Results["whois.nic.uk"]["uk"]["found"].Count);
        Assert.Null(results.Results["whois.nic.uk"]["uk"]["found"]["google.co.uk"].Error);
        Assert.NotNull(results.Results["whois.nic.uk"]["uk"]["found"]["bbc.co.uk"].Error);
    }

    [Fact]
    public async Task RunAsync_RateGroups_QueriesGroupsInParallel()
    {
        // Two servers in the same rate group + one independent
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.verisign-grs.com"] = new("com", false, "verisign", new Dictionary<string, List<string>>
            {
                ["found"] = ["google.com"]
            }),
            ["ccwhois.verisign-grs.com"] = new("cc", false, "verisign", new Dictionary<string, List<string>>
            {
                ["found"] = ["example.cc"]
            }),
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns("Domain Name: test\r\n");
        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(true);

        var results = await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        // All 3 domains queried
        Assert.True(results.Results.ContainsKey("whois.verisign-grs.com"));
        Assert.True(results.Results.ContainsKey("ccwhois.verisign-grs.com"));
        Assert.True(results.Results.ContainsKey("whois.nic.uk"));
    }

    [Fact]
    public async Task RunAsync_CreatesDirectoryIfMissing()
    {
        var registry = new DomainRegistryData(new Dictionary<string, ServerEntry>
        {
            ["whois.nic.uk"] = new("uk", false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

        _tcpReader.Read(Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string>(),
                Arg.Any<Encoding>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns("Domain Name: google.co.uk\r\n");
        _fileSystem.DirectoryExists(Arg.Any<string>()).Returns(false);

        await CreateEngine().RunAsync(registry, _options, CancellationToken.None);

        _fileSystem.Received(1).CreateDirectory("/repo/tests/Whois.Tests/Samples/whois.nic.uk/uk/found");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "RefreshEngineTests"`
Expected: FAIL — `RefreshEngine`, `RefreshEngineOptions` don't exist.

- [ ] **Step 3: Implement RefreshEngine**

`tools/WhoisRefresh/Domain/RefreshEngine.cs`:
```csharp
using System.Net.Sockets;
using System.Text;
using Whois.Net;
using Whois.Parsers;
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Domain;

public record RefreshEngineOptions(
    string SamplesBasePath,
    TimeSpan DelayBetweenQueries,
    int QueryTimeoutSeconds,
    int MaxResponseBytes);

public class RefreshEngine
{
    private readonly ITcpReader _tcpReader;
    private readonly IFileSystem _fileSystem;

    public RefreshEngine(ITcpReader tcpReader, IFileSystem fileSystem)
    {
        _tcpReader = tcpReader;
        _fileSystem = fileSystem;
    }

    public async Task<RefreshResults> RunAsync(
        DomainRegistryData registry,
        RefreshEngineOptions options,
        CancellationToken cancellationToken)
    {
        var results = new RefreshResults
        {
            Version = DateTimeOffset.UtcNow,
            Results = new()
        };

        var groups = registry.GetRateGroups();

        var tasks = groups.Select(group =>
            ProcessRateGroupAsync(group, options, results, cancellationToken));

        await Task.WhenAll(tasks);

        return results;
    }

    private async Task ProcessRateGroupAsync(
        IGrouping<string, KeyValuePair<string, ServerEntry>> group,
        RefreshEngineOptions options,
        RefreshResults results,
        CancellationToken cancellationToken)
    {
        var isFirst = true;

        foreach (var (serverName, server) in group)
        {
            foreach (var (status, domains) in server.Domains)
            {
                foreach (var domain in domains)
                {
                    if (!isFirst && options.DelayBetweenQueries > TimeSpan.Zero)
                    {
                        await Task.Delay(options.DelayBetweenQueries, cancellationToken);
                    }
                    isFirst = false;

                    var domainResult = await QueryDomainAsync(
                        serverName, server.Tld, status, domain, options, cancellationToken);

                    RecordResult(results, serverName, server.Tld, status, domain, domainResult);
                }
            }
        }
    }

    private async Task<DomainResult> QueryDomainAsync(
        string serverName, string tld, string status, string domain,
        RefreshEngineOptions options, CancellationToken cancellationToken)
    {
        var result = new DomainResult
        {
            Timestamp = DateTimeOffset.UtcNow
        };

        try
        {
            var response = await _tcpReader.Read(
                serverName, 43, $"{domain}\r\n",
                Encoding.UTF8, options.QueryTimeoutSeconds, cancellationToken);

            if (response.Length > options.MaxResponseBytes)
            {
                result.Error = new QueryError
                {
                    Type = QueryErrorType.ResponseTooLarge,
                    Message = $"Response size {response.Length} exceeds maximum {options.MaxResponseBytes}",
                    Detail = $"{serverName}:43"
                };
                response = response[..options.MaxResponseBytes];
            }

            // Parse response
            var parser = new WhoisParser();
            var parsed = parser.Parse(serverName, response);

            result.MatchedTemplate = parsed.TemplateName;
            result.ExtractedFields = GetExtractedFieldNames(parsed);

            // Determine actual status for save directory
            var actualStatus = MapWhoisStatus(parsed.Status);
            var saveStatus = actualStatus ?? status;
            if (actualStatus != null && actualStatus != status)
            {
                result.ActualStatus = actualStatus;
            }

            // Save response to the actual status directory
            var dir = Path.Combine(options.SamplesBasePath, serverName, tld, saveStatus);
            if (!_fileSystem.DirectoryExists(dir))
            {
                _fileSystem.CreateDirectory(dir);
            }
            var filePath = Path.Combine(dir, $"{domain}.txt");
            await _fileSystem.WriteAllTextAsync(filePath, response, cancellationToken);

            if (result.Error == null && parsed.TemplateName == null)
            {
                result.Error = new QueryError
                {
                    Type = QueryErrorType.ParseFailure,
                    Message = "No template matched",
                    Detail = $"{serverName}/{tld}/{status}/{domain}"
                };
            }
        }
        catch (OperationCanceledException)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Timeout,
                Message = "Query timed out",
                Detail = $"{serverName}:43"
            };
        }
        catch (SocketException ex)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.ConnectionRefused,
                Message = ex.Message,
                Detail = $"{serverName}:43"
            };
        }
        catch (Exception ex)
        {
            result.Error = new QueryError
            {
                Type = QueryErrorType.Unknown,
                Message = ex.Message,
                Detail = $"{serverName}:43"
            };
        }

        return result;
    }

    private static List<string> GetExtractedFieldNames(Whois.WhoisResponse parsed)
    {
        var fields = new List<string>();
        if (parsed.DomainName != null) fields.Add("DomainName");
        if (parsed.Registrar != null) fields.Add("Registrar");
        if (parsed.Registered != null) fields.Add("Registered");
        if (parsed.Updated != null) fields.Add("Updated");
        if (parsed.Expiration != null) fields.Add("Expiration");
        if (parsed.NameServers.Count > 0) fields.Add("NameServers");
        if (parsed.DomainStatus.Count > 0) fields.Add("DomainStatus");
        if (parsed.Registrant != null) fields.Add("Registrant");
        if (parsed.TechnicalContact != null) fields.Add("TechnicalContact");
        if (parsed.AdminContact != null) fields.Add("AdminContact");
        if (parsed.BillingContact != null) fields.Add("BillingContact");
        if (parsed.DnsSecStatus != null) fields.Add("DnsSecStatus");
        if (parsed.RegistryDomainId != null) fields.Add("RegistryDomainId");
        return fields;
    }

    private static string? MapWhoisStatus(Whois.WhoisStatus status) => status switch
    {
        Whois.WhoisStatus.Found => "found",
        Whois.WhoisStatus.NotFound => "not-found",
        Whois.WhoisStatus.Throttled => "throttled",
        Whois.WhoisStatus.Reserved => "reserved",
        Whois.WhoisStatus.Suspended => "suspended",
        Whois.WhoisStatus.Inactive => "inactive",
        Whois.WhoisStatus.Expired => "expired",
        Whois.WhoisStatus.Unknown => null,
        _ => null
    };

    private static void RecordResult(
        RefreshResults results, string server, string tld, string status,
        string domain, DomainResult domainResult)
    {
        lock (results)
        {
            if (!results.Results.ContainsKey(server))
                results.Results[server] = new();
            if (!results.Results[server].ContainsKey(tld))
                results.Results[server][tld] = new();
            if (!results.Results[server][tld].ContainsKey(status))
                results.Results[server][tld][status] = new();

            results.Results[server][tld][status][domain] = domainResult;
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "RefreshEngineTests"`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/
git commit -m "feat(refresh): implement RefreshEngine with rate group parallelism and error handling"
```

---

### Task 5: Drift Classification + Report Generation

**Files:**
- Create: `tools/WhoisRefresh/Domain/DriftClassifier.cs`
- Create: `tools/WhoisRefresh/Domain/DriftReport.cs`
- Create: `tests/WhoisRefresh.Tests/DriftClassifierTests.cs`

**Interfaces:**
- Consumes: `RefreshResults`, `DomainResult` from Task 3
- Consumes: `DomainRegistryData` from Task 1
- Produces: `DriftClassifier.Classify(RefreshResults baseline, RefreshResults current, DomainRegistryData registry)` → `List<DriftEntry>`
- Produces: `DriftEntry` record: `{ Server, Tld, Status, Domain, Classification (DriftClassification enum), Severity (DriftSeverity enum), Details, PreviousTemplate, CurrentTemplate, PreviousFields, CurrentFields }`
- Produces: `DriftClassification` enum: `NoMatch, FieldRegression, TemplateShift, StatusMismatch, NewEntry, QueryError`
- Produces: `DriftSeverity` enum: `Breakage, Drift, Info, Warning`
- Produces: `DriftReportGenerator.ToJson(List<DriftEntry>)` → `string`
- Produces: `DriftReportGenerator.ToMarkdown(List<DriftEntry>)` → `string`

- [ ] **Step 1: Write failing tests for DriftClassifier**

`tests/WhoisRefresh.Tests/DriftClassifierTests.cs`:
```csharp
using WhoisRefresh.Domain;

namespace WhoisRefresh.Tests;

public class DriftClassifierTests
{
    private static DomainRegistryData SimpleRegistry(string server = "whois.nic.uk", string tld = "uk") =>
        new(new Dictionary<string, ServerEntry>
        {
            [server] = new(tld, false, null, new Dictionary<string, List<string>>
            {
                ["found"] = ["google.co.uk"]
            })
        });

    private static RefreshResults MakeResults(string? template, List<string> fields, QueryError? error = null) =>
        new()
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
                                MatchedTemplate = template,
                                ExtractedFields = fields,
                                Error = error
                            }
                        }
                    }
                }
            }
        };

    [Fact]
    public void Classify_NoMatch_WhenPreviouslyMatchedNowDoesNot()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults(null, []);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NoMatch, entries[0].Classification);
        Assert.Equal(DriftSeverity.Breakage, entries[0].Severity);
    }

    [Fact]
    public void Classify_FieldRegression_WhenFewerFieldsExtracted()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar", "Expiration"]);
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.FieldRegression, entries[0].Classification);
        Assert.Equal(DriftSeverity.Breakage, entries[0].Severity);
    }

    [Fact]
    public void Classify_TemplateShift_WhenDifferentTemplateButEqualOrMoreFields()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults("whois.nic.uk/uk/found/02", ["DomainName", "Registrar", "Expiration"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.TemplateShift, entries[0].Classification);
        Assert.Equal(DriftSeverity.Info, entries[0].Severity);
    }

    [Fact]
    public void Classify_StatusMismatch_WhenActualStatusDiffersFromExpected()
    {
        // Domain is listed under "found" in registry, result recorded under "found"
        // but ActualStatus shows it parsed as "not-found"
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
                                MatchedTemplate = "whois.nic.uk/uk/not-found/01",
                                ExtractedFields = ["DomainName"],
                                Error = null,
                                ActualStatus = "not-found"
                            }
                        }
                    }
                }
            }
        };
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        // Registry says domain should be "found"
        var registry = SimpleRegistry();

        var entries = DriftClassifier.Classify(baseline, current, registry);

        Assert.Contains(entries, e => e.Classification == DriftClassification.StatusMismatch);
    }

    [Fact]
    public void Classify_NewEntry_WhenNoBaseline()
    {
        var baseline = new RefreshResults { Version = DateTimeOffset.UtcNow, Results = new() };
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NewEntry, entries[0].Classification);
        Assert.Equal(DriftSeverity.Info, entries[0].Severity);
    }

    [Fact]
    public void Classify_QueryError_RecordsWarning()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults(null, [], new QueryError
        {
            Type = QueryErrorType.Timeout,
            Message = "Timed out"
        });

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Single(entries);
        Assert.Equal(DriftClassification.QueryError, entries[0].Classification);
        Assert.Equal(DriftSeverity.Warning, entries[0].Severity);
    }

    [Fact]
    public void Classify_NoDrift_WhenResultsIdentical()
    {
        var baseline = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);
        var current = MakeResults("whois.nic.uk/uk/found/01", ["DomainName", "Registrar"]);

        var entries = DriftClassifier.Classify(baseline, current, SimpleRegistry());

        Assert.Empty(entries);
    }

    [Fact]
    public void ToMarkdown_GeneratesValidReport()
    {
        var entries = new List<DriftEntry>
        {
            new("whois.nic.uk", "uk", "found", "google.co.uk",
                DriftClassification.NoMatch, DriftSeverity.Breakage,
                "Previously matched whois.nic.uk/uk/found/01, now matches nothing",
                "whois.nic.uk/uk/found/01", null, ["DomainName", "Registrar"], [])
        };

        var markdown = DriftReportGenerator.ToMarkdown(entries);

        Assert.Contains("google.co.uk", markdown);
        Assert.Contains("Breakage", markdown);
        Assert.Contains("No match", markdown);
    }

    [Fact]
    public void ToJson_RoundTrips()
    {
        var entries = new List<DriftEntry>
        {
            new("whois.nic.uk", "uk", "found", "google.co.uk",
                DriftClassification.FieldRegression, DriftSeverity.Breakage,
                "Fields reduced from 3 to 1",
                "whois.nic.uk/uk/found/01", "whois.nic.uk/uk/found/01",
                ["DomainName", "Registrar", "Expiration"], ["DomainName"])
        };

        var json = DriftReportGenerator.ToJson(entries);
        var deserialized = DriftReportGenerator.FromJson(json);

        Assert.Single(deserialized);
        Assert.Equal("google.co.uk", deserialized[0].Domain);
        Assert.Equal(DriftClassification.FieldRegression, deserialized[0].Classification);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "DriftClassifierTests"`
Expected: FAIL — types don't exist.

- [ ] **Step 3: Implement DriftClassifier**

`tools/WhoisRefresh/Domain/DriftClassifier.cs`:
```csharp
namespace WhoisRefresh.Domain;

public enum DriftClassification
{
    NoMatch,
    FieldRegression,
    TemplateShift,
    StatusMismatch,
    NewEntry,
    QueryError
}

public enum DriftSeverity
{
    Breakage,
    Drift,
    Info,
    Warning
}

public record DriftEntry(
    string Server,
    string Tld,
    string Status,
    string Domain,
    DriftClassification Classification,
    DriftSeverity Severity,
    string Details,
    string? PreviousTemplate,
    string? CurrentTemplate,
    List<string> PreviousFields,
    List<string> CurrentFields);

public static class DriftClassifier
{
    public static List<DriftEntry> Classify(
        RefreshResults baseline,
        RefreshResults current,
        DomainRegistryData registry)
    {
        var entries = new List<DriftEntry>();

        foreach (var (server, tlds) in current.Results)
        {
            foreach (var (tld, statuses) in tlds)
            {
                foreach (var (status, domains) in statuses)
                {
                    foreach (var (domain, currentResult) in domains)
                    {
                        var baselineResult = GetBaselineResult(baseline, server, tld, domain);
                        var expectedStatus = GetExpectedStatus(registry, server, domain);

                        var entry = ClassifyDomain(
                            server, tld, status, domain,
                            baselineResult, currentResult, expectedStatus);

                        if (entry != null)
                        {
                            entries.Add(entry);
                        }
                    }
                }
            }
        }

        return entries;
    }

    private static DriftEntry? ClassifyDomain(
        string server, string tld, string status, string domain,
        DomainResult? baselineResult, DomainResult currentResult,
        string? expectedStatus)
    {
        // Query error
        if (currentResult.Error != null && currentResult.Error.Type != QueryErrorType.ParseFailure)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.QueryError, DriftSeverity.Warning,
                $"Query failed: {currentResult.Error.Type} — {currentResult.Error.Message}",
                baselineResult?.MatchedTemplate, null,
                baselineResult?.ExtractedFields ?? [], []);
        }

        // No baseline — new entry
        if (baselineResult == null)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.NewEntry, DriftSeverity.Info,
                "New domain, no baseline to compare",
                null, currentResult.MatchedTemplate,
                [], currentResult.ExtractedFields);
        }

        // Status mismatch (ActualStatus set by RefreshEngine when parsed status differs from expected)
        if (currentResult.ActualStatus != null && currentResult.ActualStatus != status)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.StatusMismatch, DriftSeverity.Drift,
                $"Expected status '{status}', got '{currentResult.ActualStatus}'",
                baselineResult.MatchedTemplate, currentResult.MatchedTemplate,
                baselineResult.ExtractedFields, currentResult.ExtractedFields);
        }

        // No match (previously matched, now doesn't)
        if (baselineResult.MatchedTemplate != null && currentResult.MatchedTemplate == null)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.NoMatch, DriftSeverity.Breakage,
                $"Previously matched {baselineResult.MatchedTemplate}, now matches nothing",
                baselineResult.MatchedTemplate, null,
                baselineResult.ExtractedFields, []);
        }

        // Field regression
        if (currentResult.ExtractedFields.Count < baselineResult.ExtractedFields.Count)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.FieldRegression, DriftSeverity.Breakage,
                $"Fields reduced from {baselineResult.ExtractedFields.Count} to {currentResult.ExtractedFields.Count}",
                baselineResult.MatchedTemplate, currentResult.MatchedTemplate,
                baselineResult.ExtractedFields, currentResult.ExtractedFields);
        }

        // Template shift (different template, same or better fields)
        if (currentResult.MatchedTemplate != baselineResult.MatchedTemplate)
        {
            return new DriftEntry(server, tld, status, domain,
                DriftClassification.TemplateShift, DriftSeverity.Info,
                $"Template changed from {baselineResult.MatchedTemplate} to {currentResult.MatchedTemplate}",
                baselineResult.MatchedTemplate, currentResult.MatchedTemplate,
                baselineResult.ExtractedFields, currentResult.ExtractedFields);
        }

        // No change
        return null;
    }

    private static DomainResult? GetBaselineResult(
        RefreshResults baseline, string server, string tld, string domain)
    {
        // Search all statuses in baseline for this domain
        if (!baseline.Results.TryGetValue(server, out var serverResults)) return null;
        if (!serverResults.TryGetValue(tld, out var tldResults)) return null;

        foreach (var (_, domains) in tldResults)
        {
            if (domains.TryGetValue(domain, out var result))
                return result;
        }

        return null;
    }

    private static string? GetExpectedStatus(DomainRegistryData registry, string server, string domain)
    {
        if (!registry.Servers.TryGetValue(server, out var serverEntry)) return null;

        foreach (var (status, domains) in serverEntry.Domains)
        {
            if (domains.Contains(domain)) return status;
        }

        return null;
    }
}
```

- [ ] **Step 4: Add ActualStatus to DomainResult**

In `tools/WhoisRefresh/Domain/RefreshResult.cs`, add to the `DomainResult` class:
```csharp
public string? ActualStatus { get; set; }
```

- [ ] **Step 5: Implement DriftReportGenerator**

`tools/WhoisRefresh/Domain/DriftReport.cs`:
```csharp
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WhoisRefresh.Domain;

public static class DriftReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static string ToJson(List<DriftEntry> entries)
    {
        return JsonSerializer.Serialize(entries, JsonOptions);
    }

    public static List<DriftEntry> FromJson(string json)
    {
        return JsonSerializer.Deserialize<List<DriftEntry>>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize drift entries");
    }

    public static string ToMarkdown(List<DriftEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Drift Report");
        sb.AppendLine();

        var breakages = entries.Where(e => e.Severity == DriftSeverity.Breakage).ToList();
        var drift = entries.Where(e => e.Severity == DriftSeverity.Drift).ToList();
        var warnings = entries.Where(e => e.Severity == DriftSeverity.Warning).ToList();
        var info = entries.Where(e => e.Severity == DriftSeverity.Info).ToList();

        if (breakages.Count > 0)
        {
            sb.AppendLine("## Breakages");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in breakages)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        if (drift.Count > 0)
        {
            sb.AppendLine("## Drift");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in drift)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        if (warnings.Count > 0)
        {
            sb.AppendLine("## Warnings");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in warnings)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        if (info.Count > 0)
        {
            sb.AppendLine("## Informational");
            sb.AppendLine();
            sb.AppendLine("| Domain | Server | Classification | Details |");
            sb.AppendLine("|--------|--------|---------------|---------|");
            foreach (var e in info)
            {
                sb.AppendLine($"| {e.Domain} | {e.Server} | {FormatClassification(e.Classification)} | {e.Details} |");
            }
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static string FormatClassification(DriftClassification classification) => classification switch
    {
        DriftClassification.NoMatch => "No match",
        DriftClassification.FieldRegression => "Field regression",
        DriftClassification.TemplateShift => "Template shift",
        DriftClassification.StatusMismatch => "Status mismatch",
        DriftClassification.NewEntry => "New entry",
        DriftClassification.QueryError => "Query error",
        _ => classification.ToString()
    };
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "DriftClassifierTests"`
Expected: All 9 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/
git commit -m "feat(refresh): implement drift classification and report generation"
```

---

### Task 6: Detect Command + IDriftReporter

**Files:**
- Create: `tools/WhoisRefresh/Infrastructure/IDriftReporter.cs`
- Create: `tools/WhoisRefresh/Infrastructure/GhCliDriftReporter.cs`
- Create: `tools/WhoisRefresh/Commands/DetectCommand.cs`
- Create: `tests/WhoisRefresh.Tests/DetectCommandTests.cs`
- Modify: `tools/WhoisRefresh/Program.cs` (register command)

**Interfaces:**
- Consumes: `DriftClassifier.Classify()` from Task 5
- Consumes: `DriftReportGenerator.ToJson()`, `.ToMarkdown()` from Task 5
- Consumes: `RefreshResults.Deserialize()` from Task 3
- Consumes: `DomainRegistry.LoadFromFileAsync()` from Task 1
- Consumes: `IFileSystem` from Task 3
- Produces: `IDriftReporter.ReportAsync(List<DriftEntry>, string markdownReport, CancellationToken)` → `Task`
- Produces: `IDriftReporter.HasHumanCommits(string branch, CancellationToken)` → `Task<bool>`

- [ ] **Step 1: Write failing tests**

`tests/WhoisRefresh.Tests/DetectCommandTests.cs`:
```csharp
using NSubstitute;
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

        fileSystem.ReadAllTextAsync(Arg.Is<string>(p => p.Contains("refresh-results.json")), Arg.Any<CancellationToken>())
            .Returns(RefreshResults.Serialize(baseline));

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(current, registry, "/repo/tools/WhoisRefresh", CancellationToken.None);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NoMatch, entries[0].Classification);

        await reporter.Received(1).ReportAsync(
            Arg.Is<List<DriftEntry>>(e => e.Count == 1),
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

        fileSystem.ReadAllTextAsync(Arg.Is<string>(p => p.Contains("refresh-results.json")), Arg.Any<CancellationToken>())
            .Returns(RefreshResults.Serialize(results));

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(results, registry, "/repo/tools/WhoisRefresh", CancellationToken.None);

        Assert.Empty(entries);
        await reporter.DidNotReceive().ReportAsync(
            Arg.Any<List<DriftEntry>>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DetectAsync_NoBaseline_AllEntriesAreNew()
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

        fileSystem.FileExists(Arg.Any<string>()).Returns(false);

        var detector = new DriftDetector(reporter, fileSystem);
        var entries = await detector.DetectAsync(current, registry, "/repo/tools/WhoisRefresh", CancellationToken.None);

        Assert.Single(entries);
        Assert.Equal(DriftClassification.NewEntry, entries[0].Classification);
        // New entries don't trigger PR
        await reporter.DidNotReceive().ReportAsync(
            Arg.Any<List<DriftEntry>>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "DetectCommandTests"`
Expected: FAIL — `IDriftReporter`, `DriftDetector` don't exist.

- [ ] **Step 3: Implement IDriftReporter and DriftDetector**

`tools/WhoisRefresh/Infrastructure/IDriftReporter.cs`:
```csharp
using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public interface IDriftReporter
{
    Task ReportAsync(List<DriftEntry> entries, string markdownReport, CancellationToken cancellationToken);
    Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken);
}
```

`tools/WhoisRefresh/Infrastructure/GhCliDriftReporter.cs`:
```csharp
using System.Diagnostics;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public class GhCliDriftReporter : IDriftReporter
{
    public async Task ReportAsync(List<DriftEntry> entries, string markdownReport, CancellationToken cancellationToken)
    {
        var branch = "template-drift";

        if (await HasHumanCommitsAsync(branch, cancellationToken))
        {
            branch = $"template-drift/{DateTime.UtcNow:yyyy-MM-dd}";
        }

        // Create/update branch and PR via gh CLI
        await RunGhAsync($"pr create --base main --head {branch} --title \"Template drift detected\" --body \"{EscapeForShell(markdownReport)}\"", cancellationToken);
    }

    public async Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunGhAsync($"api repos/{{owner}}/{{repo}}/compare/main...{branch} --jq '.ahead_by'", cancellationToken);
            return int.TryParse(result.Trim(), out var ahead) && ahead > 0;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string> RunGhAsync(string arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo("gh", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start gh process");

        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        return output;
    }

    private static string EscapeForShell(string input)
    {
        return input.Replace("\"", "\\\"").Replace("\n", "\\n");
    }
}
```

`tools/WhoisRefresh/Domain/DriftDetector.cs` (new file):
```csharp
using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Domain;

public class DriftDetector
{
    private readonly IDriftReporter _reporter;
    private readonly IFileSystem _fileSystem;

    public DriftDetector(IDriftReporter reporter, IFileSystem fileSystem)
    {
        _reporter = reporter;
        _fileSystem = fileSystem;
    }

    public async Task<List<DriftEntry>> DetectAsync(
        RefreshResults current,
        DomainRegistryData registry,
        string toolDirectory,
        CancellationToken cancellationToken)
    {
        var baselinePath = Path.Combine(toolDirectory, "refresh-results.json");

        RefreshResults baseline;
        if (_fileSystem.FileExists(baselinePath))
        {
            var baselineJson = await _fileSystem.ReadAllTextAsync(baselinePath, cancellationToken);
            baseline = RefreshResults.Deserialize(baselineJson);
        }
        else
        {
            baseline = new RefreshResults { Version = DateTimeOffset.MinValue, Results = new() };
        }

        var entries = DriftClassifier.Classify(baseline, current, registry);

        var hasBreakages = entries.Any(e => e.Severity == DriftSeverity.Breakage);

        if (hasBreakages)
        {
            var markdown = DriftReportGenerator.ToMarkdown(entries);
            await _reporter.ReportAsync(entries, markdown, cancellationToken);
        }

        return entries;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "DetectCommandTests"`
Expected: All 3 tests PASS.

- [ ] **Step 5: Implement DetectCommand**

`tools/WhoisRefresh/Commands/DetectCommand.cs`:
```csharp
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
        var entries = await detector.DetectAsync(current, registry, toolDir, CancellationToken.None);

        // Output results
        var isCi = Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";
        OutputResults(entries, isCi);

        // Write reports
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
                AnsiConsole.MarkupLine($"[{color}]{entry.Severity}[/] {entry.Domain} ({entry.Server}): {entry.Details}");
            }
        }
    }
}
```

- [ ] **Step 6: Register detect command in Program.cs**

Update `tools/WhoisRefresh/Program.cs`:
```csharp
using Spectre.Console.Cli;
using WhoisRefresh.Commands;
using WhoisRefresh.Infrastructure;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
    config.AddCommand<DetectCommand>("detect")
        .WithDescription("Compare refresh results against baseline, detect drift");
});

return await app.RunAsync(args);
```

Note: `DetectCommand` has constructor dependencies (`IDriftReporter`, `IFileSystem`). Spectre.Cli supports DI via a type registrar. Add a simple registrar or refactor to use a factory pattern. For now, the simplest approach is to make the dependencies resolvable via a static service configuration or pass them through a custom `ITypeRegistrar`. The implementer should wire this up using Spectre.Cli's `ITypeRegistrar` pattern:

```csharp
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using WhoisRefresh.Commands;
using WhoisRefresh.Infrastructure;

var services = new ServiceCollection();
services.AddSingleton<IFileSystem, PhysicalFileSystem>();
services.AddSingleton<IDriftReporter, GhCliDriftReporter>();

var registrar = new TypeRegistrar(services);
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
    config.AddCommand<DetectCommand>("detect")
        .WithDescription("Compare refresh results against baseline, detect drift");
});

return await app.RunAsync(args);
```

The `TypeRegistrar` class is a standard Spectre.Cli pattern — create `tools/WhoisRefresh/Infrastructure/TypeRegistrar.cs`:
```csharp
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace WhoisRefresh.Infrastructure;

public sealed class TypeRegistrar : ITypeRegistrar
{
    private readonly IServiceCollection _services;

    public TypeRegistrar(IServiceCollection services)
    {
        _services = services;
    }

    public ITypeResolver Build()
    {
        return new TypeResolver(_services.BuildServiceProvider());
    }

    public void Register(Type service, Type implementation)
    {
        _services.AddSingleton(service, implementation);
    }

    public void RegisterInstance(Type service, object implementation)
    {
        _services.AddSingleton(service, implementation);
    }

    public void RegisterLazy(Type service, Func<object> factory)
    {
        _services.AddSingleton(service, _ => factory());
    }
}

public sealed class TypeResolver : ITypeResolver
{
    private readonly IServiceProvider _provider;

    public TypeResolver(IServiceProvider provider)
    {
        _provider = provider;
    }

    public object? Resolve(Type? type)
    {
        return type == null ? null : _provider.GetService(type);
    }
}
```

Add to `WhoisRefresh.csproj`:
```xml
<PackageReference Include="Microsoft.Extensions.DependencyInjection" />
```

- [ ] **Step 7: Build and verify**

Run: `dotnet build Whois.sln`
Expected: Build succeeded.

- [ ] **Step 8: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/
git commit -m "feat(refresh): implement detect command with drift detection and IDriftReporter"
```

---

### Task 7: Refresh Command Wiring + Console Output

**Files:**
- Create: `tools/WhoisRefresh/Commands/RefreshCommand.cs`
- Create: `tools/WhoisRefresh/Infrastructure/ConsoleOutput.cs`
- Modify: `tools/WhoisRefresh/Program.cs` (register refresh command)
- Create: `tools/WhoisRefresh/.gitignore`

**Interfaces:**
- Consumes: `DomainRegistry.LoadFromFileAsync()` from Task 1
- Consumes: `RefreshEngine.RunAsync()` from Task 4
- Consumes: `RefreshResults.Serialize()`, `.Prune()` from Task 3
- Consumes: `IFileSystem` from Task 3
- Consumes: `ITcpReader` from main Whois library
- Produces: Full CLI integration — `refresh` command wired up and functional

- [ ] **Step 1: Implement ConsoleOutput helper**

`tools/WhoisRefresh/Infrastructure/ConsoleOutput.cs`:
```csharp
using Spectre.Console;

namespace WhoisRefresh.Infrastructure;

public static class ConsoleOutput
{
    public static bool IsCi => Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";

    public static void WriteInfo(string message)
    {
        if (IsCi)
            Console.WriteLine(message);
        else
            AnsiConsole.MarkupLine($"[blue]{Markup.Escape(message)}[/]");
    }

    public static void WriteSuccess(string message)
    {
        if (IsCi)
            Console.WriteLine(message);
        else
            AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");
    }

    public static void WriteWarning(string message)
    {
        if (IsCi)
            Console.WriteLine($"::warning::{message}");
        else
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(message)}[/]");
    }

    public static void WriteError(string message)
    {
        if (IsCi)
            Console.WriteLine($"::error::{message}");
        else
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");
    }
}
```

- [ ] **Step 2: Implement RefreshCommand**

`tools/WhoisRefresh/Commands/RefreshCommand.cs`:
```csharp
using Spectre.Console;
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

        var registry = await DomainRegistry.LoadFromFileAsync(registryPath);

        var queryableServers = registry.Servers.Count(s => !s.Value.IsStatic);
        var totalDomains = registry.Servers
            .Where(s => !s.Value.IsStatic)
            .SelectMany(s => s.Value.Domains.Values)
            .Sum(d => d.Count);

        ConsoleOutput.WriteInfo($"Querying {totalDomains} domains across {queryableServers} servers...");

        var options = new RefreshEngineOptions(
            SamplesBasePath: samplesPath,
            DelayBetweenQueries: TimeSpan.FromMilliseconds(settings.DelayMs),
            QueryTimeoutSeconds: settings.TimeoutSeconds,
            MaxResponseBytes: settings.MaxResponseBytes);

        var engine = new RefreshEngine(_tcpReader, _fileSystem);
        var results = await engine.RunAsync(registry, options, CancellationToken.None);

        // Prune removed domains
        results.Prune(registry);

        // Write results
        var json = RefreshResults.Serialize(results);
        await _fileSystem.WriteAllTextAsync(resultsPath, json);

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

        ConsoleOutput.WriteSuccess($"Refresh complete: {successes} succeeded, {errors} failed");

        if (errors > 0)
        {
            ConsoleOutput.WriteWarning($"{errors} queries failed — check refresh-results.json for details");
        }

        return 0;
    }
}
```

- [ ] **Step 3: Update Program.cs with all commands**

`tools/WhoisRefresh/Program.cs`:
```csharp
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using Whois.Net;
using WhoisRefresh.Commands;
using WhoisRefresh.Infrastructure;

var services = new ServiceCollection();
services.AddSingleton<IFileSystem, PhysicalFileSystem>();
services.AddSingleton<IDriftReporter, GhCliDriftReporter>();
services.AddSingleton<ITcpReader, TcpReader>();

var registrar = new TypeRegistrar(services);
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
    config.AddCommand<RefreshCommand>("refresh")
        .WithDescription("Query live WHOIS servers and save responses");
    config.AddCommand<DetectCommand>("detect")
        .WithDescription("Compare refresh results against baseline, detect drift");
});

return await app.RunAsync(args);
```

- [ ] **Step 4: Create .gitignore for generated artifacts**

`tools/WhoisRefresh/.gitignore`:
```
drift-report.json
drift-report.md
```

- [ ] **Step 5: Build and verify full solution**

Run: `dotnet build Whois.sln`
Expected: Build succeeded.

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add tools/WhoisRefresh/ tests/WhoisRefresh.Tests/
git commit -m "feat(refresh): wire up refresh command, console output, and complete CLI integration"
```
