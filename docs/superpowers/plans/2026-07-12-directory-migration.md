# Directory Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate template and sample files from flat `{server}/{tld}/{StatusName}.txt` to normalised `{server}/{tld}/{status}/{nn}.txt` directory structure, with all tests passing.

**Architecture:** A one-time migration tool (`tools/WhoisMigration/`) maps old paths to new paths, moves files, and updates template front matter. `SampleReader` gets a `status` parameter. ResourceReader and WhoisParser require no changes (prefix-based resource enumeration still works with the new deeper structure). ~200 parsing test classes get scripted updates.

**Tech Stack:** .NET (netstandard2.0/net8.0/net10.0), xUnit, Spectre.Cli (optional for migration CLI)

## Global Constraints

- Target frameworks: `netstandard2.0`, `net8.0`, `net10.0`
- `LangVersion=latest`, `Nullable=enable`, `ImplicitUsings=enable`, `TreatWarningsAsErrors=true`
- Central Package Management via `Directory.Packages.props`
- Templates are embedded resources via `<EmbeddedResource Include="Resources\**\*.txt" />`
- Samples are plain files on disk, read via relative paths from test output directory
- Template naming: all lowercase, kebab-case status, sequential numbering (`01.txt`, `02.txt`)
- Sample naming: all lowercase, kebab-case status directories, original filenames preserved (domain-based naming deferred to Plan 2)

---

### Task 1: Template status mapping logic + tests

**Files:**
- Create: `tools/WhoisMigration/WhoisMigration.csproj`
- Create: `tools/WhoisMigration/TemplateMapper.cs`
- Create: `tools/WhoisMigration.Tests/WhoisMigration.Tests.csproj`
- Create: `tools/WhoisMigration.Tests/TemplateMapperTests.cs`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `TemplateMapper.ExtractStatus(string templateContent) → string` — parses `set: Status = X` from front matter
  - `TemplateMapper.ToStatusDirectory(string pascalCaseStatus) → string` — converts `NotFound` → `not-found`
  - `TemplateMapper.AssignNumbers(List<string> filenames) → Dictionary<string, string>` — assigns sequential numbers within a group, sorted alphabetically: `{"Found": "01", "Found01": "02", "FoundRegistered": "03"}`
  - `TemplateMapper.UpdateFrontMatterName(string content, string newName) → string` — replaces `name:` value in template front matter

- [ ] **Step 1: Create migration tool project**

```bash
cd /Users/work/Source/whois
mkdir -p tools/WhoisMigration tools/WhoisMigration.Tests
```

Create `tools/WhoisMigration/WhoisMigration.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
</Project>
```

Create `tools/WhoisMigration.Tests/WhoisMigration.Tests.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="xunit" />
    <PackageReference Include="xunit.runner.visualstudio" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\WhoisMigration\WhoisMigration.csproj" />
  </ItemGroup>
</Project>
```

Add both projects to the solution:
```bash
dotnet sln Whois.sln add tools/WhoisMigration/WhoisMigration.csproj
dotnet sln Whois.sln add tools/WhoisMigration.Tests/WhoisMigration.Tests.csproj
```

Verify: `dotnet build tools/WhoisMigration.Tests/WhoisMigration.Tests.csproj`

- [ ] **Step 2: Write failing tests for ExtractStatus**

Create `tools/WhoisMigration.Tests/TemplateMapperTests.cs`:
```csharp
using Xunit;

namespace WhoisMigration.Tests;

public class TemplateMapperTests
{
    [Theory]
    [InlineData("---\nname: whois.nic.tr/tr/Found\ntag: whois.nic.tr\nset: Status = Found\n---\n", "Found")]
    [InlineData("---\nname: whois.nic.tr/tr/NotFound\nset: Status = NotFound\n---\n", "NotFound")]
    [InlineData("---\nname: generic/tld/Throttled01\nset: Status = Throttled\n---\n", "Throttled")]
    [InlineData("---\n# Comment\nset:  Status  =  Reserved\n---\n", "Reserved")]
    public void ExtractStatus_returns_status_from_front_matter(string content, string expected)
    {
        var result = TemplateMapper.ExtractStatus(content);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ExtractStatus_throws_when_no_status_directive()
    {
        var content = "---\nname: test\ntag: test\n---\nNo status here";
        Assert.Throws<InvalidOperationException>(() => TemplateMapper.ExtractStatus(content));
    }
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "ExtractStatus"`
Expected: FAIL — `TemplateMapper` does not exist.

- [ ] **Step 3: Implement ExtractStatus**

Create `tools/WhoisMigration/TemplateMapper.cs`:
```csharp
using System.Text.RegularExpressions;

namespace WhoisMigration;

public static partial class TemplateMapper
{
    [GeneratedRegex(@"set:\s*Status\s*=\s*(\w+)")]
    private static partial Regex StatusDirectivePattern();

    public static string ExtractStatus(string templateContent)
    {
        var match = StatusDirectivePattern().Match(templateContent);
        if (match.Success) return match.Groups[1].Value;
        throw new InvalidOperationException("Template missing 'set: Status = ...' directive in front matter");
    }
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "ExtractStatus"`
Expected: PASS

- [ ] **Step 4: Write failing tests for ToStatusDirectory**

Add to `TemplateMapperTests.cs`:
```csharp
[Theory]
[InlineData("Found", "found")]
[InlineData("NotFound", "not-found")]
[InlineData("OutOfService", "out-of-service")]
[InlineData("PendingDelete", "pending-delete")]
[InlineData("ToBeReleased", "to-be-released")]
[InlineData("NotAvailable", "not-available")]
[InlineData("NotAssigned", "not-assigned")]
[InlineData("Throttled", "throttled")]
[InlineData("Error", "error")]
public void ToStatusDirectory_converts_pascal_case_to_kebab_case(string input, string expected)
{
    var result = TemplateMapper.ToStatusDirectory(input);
    Assert.Equal(expected, result);
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "ToStatusDirectory"`
Expected: FAIL — method does not exist.

- [ ] **Step 5: Implement ToStatusDirectory**

Add to `TemplateMapper.cs`:
```csharp
[GeneratedRegex(@"(?<!^)([A-Z])")]
private static partial Regex PascalCaseBoundary();

public static string ToStatusDirectory(string pascalCaseStatus)
{
    return PascalCaseBoundary().Replace(pascalCaseStatus, "-$1").ToLowerInvariant();
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "ToStatusDirectory"`
Expected: PASS

- [ ] **Step 6: Write failing tests for AssignNumbers**

Add to `TemplateMapperTests.cs`:
```csharp
[Fact]
public void AssignNumbers_assigns_sequential_numbers_alphabetically()
{
    var filenames = new List<string> { "Found01", "Found", "Found02" };
    var result = TemplateMapper.AssignNumbers(filenames);

    Assert.Equal("01", result["Found"]);
    Assert.Equal("02", result["Found01"]);
    Assert.Equal("03", result["Found02"]);
}

[Fact]
public void AssignNumbers_single_file_gets_01()
{
    var filenames = new List<string> { "NotFound" };
    var result = TemplateMapper.AssignNumbers(filenames);

    Assert.Equal("01", result["NotFound"]);
}

[Fact]
public void AssignNumbers_handles_mixed_variants()
{
    var filenames = new List<string> { "FoundRegistered", "Found", "FoundV1" };
    var result = TemplateMapper.AssignNumbers(filenames);

    Assert.Equal("01", result["Found"]);
    Assert.Equal("02", result["FoundRegistered"]);
    Assert.Equal("03", result["FoundV1"]);
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "AssignNumbers"`
Expected: FAIL — method does not exist.

- [ ] **Step 7: Implement AssignNumbers**

Add to `TemplateMapper.cs`:
```csharp
public static Dictionary<string, string> AssignNumbers(List<string> filenames)
{
    var sorted = filenames.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    var result = new Dictionary<string, string>();
    for (var i = 0; i < sorted.Count; i++)
    {
        result[sorted[i]] = (i + 1).ToString("D2");
    }
    return result;
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "AssignNumbers"`
Expected: PASS

- [ ] **Step 8: Write failing tests for UpdateFrontMatterName**

Add to `TemplateMapperTests.cs`:
```csharp
[Fact]
public void UpdateFrontMatterName_replaces_name_in_front_matter()
{
    var content = "---\n#\n# .tr Parsing Template\n#\nname: whois.nic.tr/tr/Found\ntag: whois.nic.tr\nset: Status = Found\n---\nContent here";
    var result = TemplateMapper.UpdateFrontMatterName(content, "whois.nic.tr/tr/found/01");

    Assert.Contains("name: whois.nic.tr/tr/found/01", result);
    Assert.DoesNotContain("name: whois.nic.tr/tr/Found", result);
    Assert.Contains("Content here", result);
}

[Fact]
public void UpdateFrontMatterName_preserves_other_front_matter()
{
    var content = "---\nname: old/name\ntag: whois.nic.tr\ntag: tr\nset: Status = Found\n---\n";
    var result = TemplateMapper.UpdateFrontMatterName(content, "new/name");

    Assert.Contains("tag: whois.nic.tr", result);
    Assert.Contains("tag: tr", result);
    Assert.Contains("set: Status = Found", result);
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "UpdateFrontMatterName"`
Expected: FAIL — method does not exist.

- [ ] **Step 9: Implement UpdateFrontMatterName**

Add to `TemplateMapper.cs`:
```csharp
[GeneratedRegex(@"^(name:\s*).+$", RegexOptions.Multiline)]
private static partial Regex NameDirectivePattern();

public static string UpdateFrontMatterName(string content, string newName)
{
    return NameDirectivePattern().Replace(content, $"${{1}}{newName}", 1);
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "UpdateFrontMatterName"`
Expected: PASS

- [ ] **Step 10: Run all migration tests and commit**

```bash
dotnet test tools/WhoisMigration.Tests/
git add tools/WhoisMigration/ tools/WhoisMigration.Tests/ Whois.sln
git commit -m "feat: add template migration mapping logic with tests"
```

---

### Task 2: Sample status mapping logic + tests

**Files:**
- Create: `tools/WhoisMigration/SampleMapper.cs`
- Create: `tools/WhoisMigration.Tests/SampleMapperTests.cs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `SampleMapper.MapToStatusDirectory(string sampleFilename) → (string Status, string Filename)` — maps `found_nameservers_with_ip.txt` → `("found", "found_nameservers_with_ip.txt")`

- [ ] **Step 1: Write failing tests for MapToStatusDirectory**

Create `tools/WhoisMigration.Tests/SampleMapperTests.cs`:
```csharp
using Xunit;

namespace WhoisMigration.Tests;

public class SampleMapperTests
{
    [Theory]
    [InlineData("found.txt", "found", "found.txt")]
    [InlineData("found_nameservers_with_ip.txt", "found", "found_nameservers_with_ip.txt")]
    [InlineData("found_contact_person.txt", "found", "found_contact_person.txt")]
    [InlineData("found_status_registered.txt", "found", "found_status_registered.txt")]
    [InlineData("not_found.txt", "not-found", "not_found.txt")]
    [InlineData("not_found_status_available.txt", "not-found", "not_found_status_available.txt")]
    [InlineData("error.txt", "error", "error.txt")]
    [InlineData("invalid.txt", "invalid", "invalid.txt")]
    [InlineData("throttled.txt", "throttled", "throttled.txt")]
    [InlineData("reserved.txt", "reserved", "reserved.txt")]
    [InlineData("blocked.txt", "blocked", "blocked.txt")]
    [InlineData("suspended.txt", "suspended", "suspended.txt")]
    [InlineData("not_assigned.txt", "not-assigned", "not_assigned.txt")]
    [InlineData("inactive.txt", "inactive", "inactive.txt")]
    [InlineData("quarantined.txt", "quarantined", "quarantined.txt")]
    [InlineData("out_of_service.txt", "out-of-service", "out_of_service.txt")]
    [InlineData("to_be_released.txt", "to-be-released", "to_be_released.txt")]
    [InlineData("unavailable.txt", "unavailable", "unavailable.txt")]
    [InlineData("prohibited.txt", "prohibited", "prohibited.txt")]
    public void MapToStatusDirectory_extracts_status_and_preserves_filename(
        string input, string expectedStatus, string expectedFilename)
    {
        var (status, filename) = SampleMapper.MapToStatusDirectory(input);
        Assert.Equal(expectedStatus, status);
        Assert.Equal(expectedFilename, filename);
    }

    [Fact]
    public void MapToStatusDirectory_throws_for_unknown_prefix()
    {
        Assert.Throws<InvalidOperationException>(() =>
            SampleMapper.MapToStatusDirectory("unknown_status.txt"));
    }
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "MapToStatusDirectory"`
Expected: FAIL — `SampleMapper` does not exist.

- [ ] **Step 2: Implement MapToStatusDirectory**

Create `tools/WhoisMigration/SampleMapper.cs`:
```csharp
namespace WhoisMigration;

public static class SampleMapper
{
    // Ordered longest-first so "not_found" matches before "not" (if it existed)
    private static readonly (string Prefix, string Status)[] StatusPrefixes =
    [
        ("not_found", "not-found"),
        ("not_assigned", "not-assigned"),
        ("not_available", "not-available"),
        ("out_of_service", "out-of-service"),
        ("to_be_released", "to-be-released"),
        ("pending_delete", "pending-delete"),
        ("found", "found"),
        ("error", "error"),
        ("throttled", "throttled"),
        ("reserved", "reserved"),
        ("invalid", "invalid"),
        ("blocked", "blocked"),
        ("suspended", "suspended"),
        ("inactive", "inactive"),
        ("quarantined", "quarantined"),
        ("unavailable", "unavailable"),
        ("prohibited", "prohibited"),
        ("expired", "expired"),
        ("deactivated", "deactivated"),
        ("failed", "failed"),
        ("locked", "locked"),
        ("redemption", "redemption"),
        ("unconfirmed", "unconfirmed"),
    ];

    public static (string Status, string Filename) MapToStatusDirectory(string sampleFilename)
    {
        var nameWithoutExt = Path.GetFileNameWithoutExtension(sampleFilename);

        foreach (var (prefix, status) in StatusPrefixes)
        {
            if (nameWithoutExt.Equals(prefix, StringComparison.OrdinalIgnoreCase) ||
                nameWithoutExt.StartsWith(prefix + "_", StringComparison.OrdinalIgnoreCase))
            {
                return (status, sampleFilename);
            }
        }

        throw new InvalidOperationException(
            $"Unknown status prefix in sample filename: '{sampleFilename}'. " +
            $"Add the prefix to SampleMapper.StatusPrefixes.");
    }
}
```

Run: `dotnet test tools/WhoisMigration.Tests/ --filter "MapToStatusDirectory"`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tools/WhoisMigration/SampleMapper.cs tools/WhoisMigration.Tests/SampleMapperTests.cs
git commit -m "feat: add sample status mapping logic with tests"
```

---

### Task 3: Migration execution, SampleReader update, test updates, and verification

This task moves all files, updates template front matter, updates `SampleReader`, and updates all parsing tests. These changes are interdependent and must happen together.

**Files:**
- Create: `tools/WhoisMigration/MigrateCommand.cs`
- Modify: `tests/Whois.Tests/SampleReader.cs`
- Modify: `tests/Whois.Tests/Parsing/**/*ParsingTests.cs` (~200 files)
- Move: `src/Whois/Resources/**/*.txt` (337 files into status subdirectories)
- Move: `tests/Whois.Tests/Samples/**/*.txt` (756 files into status subdirectories)

**Interfaces:**
- Consumes:
  - `TemplateMapper.ExtractStatus(string content) → string`
  - `TemplateMapper.ToStatusDirectory(string pascalCaseStatus) → string`
  - `TemplateMapper.AssignNumbers(List<string> filenames) → Dictionary<string, string>`
  - `TemplateMapper.UpdateFrontMatterName(string content, string newName) → string`
  - `SampleMapper.MapToStatusDirectory(string sampleFilename) → (string Status, string Filename)`
- Produces: migrated file structure, updated tests

- [ ] **Step 1: Write the migration command**

Create `tools/WhoisMigration/MigrateCommand.cs`:
```csharp
using System.Security.Cryptography;

namespace WhoisMigration;

public class MigrateCommand
{
    public record MigrationResult(
        int TemplatesMoved,
        int SamplesMoved,
        int TemplatesFrontMatterUpdated,
        List<string> Errors,
        Dictionary<string, string> TemplateNameMap);

    public static MigrationResult Execute(string repoRoot, bool dryRun = false)
    {
        var errors = new List<string>();
        var templateNameMap = new Dictionary<string, string>();
        var templatesMoved = 0;
        var samplesMoved = 0;
        var frontMatterUpdated = 0;

        // --- Migrate templates ---
        var resourcesDir = Path.Combine(repoRoot, "src", "Whois", "Resources");
        templatesMoved = MigrateTemplates(resourcesDir, dryRun, errors, templateNameMap);
        frontMatterUpdated = templatesMoved;

        // --- Migrate samples ---
        var samplesDir = Path.Combine(repoRoot, "tests", "Whois.Tests", "Samples");
        samplesMoved = MigrateSamples(samplesDir, dryRun, errors);

        return new MigrationResult(templatesMoved, samplesMoved, frontMatterUpdated, errors, templateNameMap);
    }

    private static int MigrateTemplates(string resourcesDir, bool dryRun, List<string> errors, Dictionary<string, string> templateNameMap)
    {
        var moved = 0;

        // Group template files by (server, tld) directory
        foreach (var tldDir in EnumerateTldDirectories(resourcesDir))
        {
            var serverName = Path.GetFileName(Path.GetDirectoryName(tldDir)!);
            var tldName = Path.GetFileName(tldDir);
            var templateFiles = Directory.GetFiles(tldDir, "*.txt");

            if (templateFiles.Length == 0) continue;

            // Group by status (extracted from front matter)
            var groups = new Dictionary<string, List<(string OldPath, string OldName)>>();
            foreach (var filePath in templateFiles)
            {
                var content = File.ReadAllText(filePath);
                var oldName = Path.GetFileNameWithoutExtension(filePath);
                try
                {
                    var status = TemplateMapper.ExtractStatus(content);
                    var statusDir = TemplateMapper.ToStatusDirectory(status);
                    if (!groups.ContainsKey(statusDir))
                        groups[statusDir] = [];
                    groups[statusDir].Add((filePath, oldName));
                }
                catch (InvalidOperationException ex)
                {
                    errors.Add($"Template {filePath}: {ex.Message}");
                }
            }

            // Assign numbers and move files
            foreach (var (statusDir, files) in groups)
            {
                var oldNames = files.Select(f => f.OldName).ToList();
                var numberMap = TemplateMapper.AssignNumbers(oldNames);

                var targetDir = Path.Combine(tldDir, statusDir);
                if (!dryRun) Directory.CreateDirectory(targetDir);

                foreach (var (oldPath, oldName) in files)
                {
                    var number = numberMap[oldName];
                    var newPath = Path.Combine(targetDir, $"{number}.txt");
                    var newFrontMatterName = $"{serverName}/{tldName}/{statusDir}/{number}";

                    var oldFrontMatterName = $"{serverName}/{tldName}/{oldName}";
                    templateNameMap[oldFrontMatterName] = newFrontMatterName;

                    if (!dryRun)
                    {
                        var content = File.ReadAllText(oldPath);
                        var updatedContent = TemplateMapper.UpdateFrontMatterName(
                            content, newFrontMatterName);
                        File.WriteAllText(newPath, updatedContent);
                        File.Delete(oldPath);
                    }

                    moved++;
                }
            }
        }

        return moved;
    }

    private static int MigrateSamples(string samplesDir, bool dryRun, List<string> errors)
    {
        var moved = 0;

        foreach (var tldDir in EnumerateTldDirectories(samplesDir))
        {
            var sampleFiles = Directory.GetFiles(tldDir, "*.txt");

            foreach (var filePath in sampleFiles)
            {
                var filename = Path.GetFileName(filePath);
                try
                {
                    var (status, _) = SampleMapper.MapToStatusDirectory(filename);
                    var targetDir = Path.Combine(tldDir, status);
                    var newPath = Path.Combine(targetDir, filename);

                    if (!dryRun)
                    {
                        Directory.CreateDirectory(targetDir);
                        File.Move(filePath, newPath);
                    }

                    moved++;
                }
                catch (InvalidOperationException ex)
                {
                    errors.Add($"Sample {filePath}: {ex.Message}");
                }
            }
        }

        return moved;
    }

    /// <summary>
    /// Enumerates directories at the {server}/{tld} level.
    /// Resources and Samples both use this two-level structure.
    /// </summary>
    private static IEnumerable<string> EnumerateTldDirectories(string rootDir)
    {
        foreach (var serverDir in Directory.GetDirectories(rootDir))
        {
            foreach (var tldDir in Directory.GetDirectories(serverDir))
            {
                yield return tldDir;
            }
        }
    }
}
```

Run: `dotnet build tools/WhoisMigration/`
Expected: BUILD SUCCEEDED

- [ ] **Step 2: Write the Program.cs entry point**

Create `tools/WhoisMigration/Program.cs`:
```csharp
using WhoisMigration;

if (args.Length < 1)
{
    Console.WriteLine("Usage: WhoisMigration <repo-root> [--dry-run]");
    return 1;
}

var repoRoot = args[0];
var dryRun = args.Contains("--dry-run");

Console.WriteLine($"Migrating: {repoRoot}");
Console.WriteLine($"Dry run: {dryRun}");

var result = MigrateCommand.Execute(repoRoot, dryRun);

Console.WriteLine($"Templates moved: {result.TemplatesMoved}");
Console.WriteLine($"Samples moved: {result.SamplesMoved}");
Console.WriteLine($"Front matter updated: {result.TemplatesFrontMatterUpdated}");

if (result.Errors.Count > 0)
{
    Console.WriteLine($"\nErrors ({result.Errors.Count}):");
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"  - {error}");
    }
    return 1;
}

Console.WriteLine("\nMigration complete.");
return 0;
```

- [ ] **Step 3: Dry-run the migration to discover any unmapped status prefixes**

```bash
cd /Users/work/Source/whois
dotnet run --project tools/WhoisMigration -- . --dry-run
```

Expected: Reports file counts for templates and samples. If there are errors (unmapped prefixes), update `SampleMapper.StatusPrefixes` or `TemplateMapper` to handle them. Re-run until dry run reports zero errors.

This step is critical — the mapping logic was written against known status values but the actual files may contain variants not yet covered. Fix any mapping gaps before proceeding.

- [ ] **Step 4: Record pre-migration file counts and content hashes**

```bash
find src/Whois/Resources -name "*.txt" | wc -l
find tests/Whois.Tests/Samples -name "*.txt" | wc -l
find src/Whois/Resources -name "*.txt" -exec shasum {} \; | sort > /tmp/pre-migration-templates.sha
find tests/Whois.Tests/Samples -name "*.txt" -exec shasum {} \; | sort > /tmp/pre-migration-samples.sha
```

Record the counts. Templates: expect ~337. Samples: expect ~756.

- [ ] **Step 5: Execute the migration**

```bash
dotnet run --project tools/WhoisMigration -- .
```

Expected: Zero errors, file counts match dry-run.

- [ ] **Step 6: Verify post-migration integrity**

```bash
# File counts must match pre-migration
find src/Whois/Resources -name "*.txt" | wc -l
find tests/Whois.Tests/Samples -name "*.txt" | wc -l

# No template files should remain at the old {server}/{tld}/*.txt level
# (all should be in {server}/{tld}/{status}/*.txt subdirectories)
find src/Whois/Resources -maxdepth 3 -name "*.txt" -not -path "*/generic/*"
# Expected: no output (all files are now at depth 4+)

# Verify sample content hashes unchanged (file contents not modified, only moved)
find tests/Whois.Tests/Samples -name "*.txt" -exec shasum {} \; | sort > /tmp/post-migration-samples.sha
# Content hashes should match — paths differ but content is identical
cut -d' ' -f1 /tmp/pre-migration-samples.sha | sort > /tmp/pre-hashes.txt
cut -d' ' -f1 /tmp/post-migration-samples.sha | sort > /tmp/post-hashes.txt
diff /tmp/pre-hashes.txt /tmp/post-hashes.txt
# Expected: no differences

# Spot-check a few template files for correct front matter
head -5 src/Whois/Resources/whois.nic.tr/tr/found/01.txt
# Expected: name: whois.nic.tr/tr/found/01
```

- [ ] **Step 7: Commit the file migration**

```bash
git add src/Whois/Resources/ tests/Whois.Tests/Samples/
git commit -m "refactor: migrate templates and samples to {server}/{tld}/{status}/ directory structure"
```

- [ ] **Step 8: Update SampleReader to accept status parameter**

Modify `tests/Whois.Tests/SampleReader.cs`:
```csharp
using System.IO;

namespace Whois
{
    public class SampleReader
    {
        public string Read(string whoisServer, string tld, string status, string sampleFileName)
        {
            var directory = Path.Combine("..", "..", "..", "Samples", whoisServer, tld, status);
            var fileName = Path.Combine(directory, sampleFileName);

            return File.ReadAllText(fileName);
        }
    }
}
```

Note: the old 3-parameter method is removed. All callers will be updated in the next step.

- [ ] **Step 9: Write test update script**

The parsing tests need two changes per test method:
1. `SampleReader.Read("server", "tld", "filename.txt")` → `SampleReader.Read("server", "tld", "status", "filename.txt")`
2. `response.TemplateName` assertions: `"server/tld/OldName"` → `"server/tld/status/nn"`

This is a scripted transformation. Write a C# script or use the migration tool to:

a) Scan each test file for `SampleReader.Read("server", "tld", "filename.txt")` calls
b) Use `SampleMapper.MapToStatusDirectory(filename)` to determine the status
c) Rewrite the call to include the status parameter
d) Scan for `Assert.Equal("server/tld/TemplateName", response.TemplateName)` assertions
e) Map the old template name to the new name using the migration's template mapping output

Add this to the migration tool. Create `tools/WhoisMigration/TestUpdater.cs`:
```csharp
using System.Text.RegularExpressions;

namespace WhoisMigration;

public static partial class TestUpdater
{
    [GeneratedRegex(
        @"SampleReader\.Read\(""([^""]+)"",\s*""([^""]+)"",\s*""([^""]+)""\)",
        RegexOptions.None)]
    private static partial Regex SampleReaderCallPattern();

    /// <summary>
    /// Updates SampleReader.Read calls to include the status parameter.
    /// </summary>
    public static string UpdateSampleReaderCalls(string testFileContent)
    {
        return SampleReaderCallPattern().Replace(testFileContent, match =>
        {
            var server = match.Groups[1].Value;
            var tld = match.Groups[2].Value;
            var filename = match.Groups[3].Value;

            var (status, _) = SampleMapper.MapToStatusDirectory(filename);

            return $"SampleReader.Read(\"{server}\", \"{tld}\", \"{status}\", \"{filename}\")";
        });
    }

    /// <summary>
    /// Updates TemplateName assertions to use new naming convention.
    /// Requires a mapping from old template names to new names,
    /// built during the template migration.
    /// </summary>
    public static string UpdateTemplateNameAssertions(
        string testFileContent,
        Dictionary<string, string> templateNameMap)
    {
        foreach (var (oldName, newName) in templateNameMap)
        {
            testFileContent = testFileContent.Replace(
                $"\"{oldName}\"",
                $"\"{newName}\"");
        }
        return testFileContent;
    }
}
```

The `templateNameMap` is built during template migration (stored in `MigrationResult.TemplateNameMap`). It maps old names like `"whois.nic.tr/tr/Found"` to new names like `"whois.nic.tr/tr/found/01"`.

- [ ] **Step 10: Execute test updates**

Add an `update-tests` command to `Program.cs` that uses the template name map from the migration result:

```csharp
// In Program.cs, add an "update-tests" mode that first runs migration
// (or loads a saved template name map), then updates test files
var migrationResult = MigrateCommand.Execute(repoRoot, dryRun: false);
var parsingTestsDir = Path.Combine(repoRoot, "tests", "Whois.Tests", "Parsing");
var testFiles = Directory.GetFiles(parsingTestsDir, "*ParsingTests.cs", SearchOption.AllDirectories);

foreach (var testFile in testFiles)
{
    var content = File.ReadAllText(testFile);
    var updated = TestUpdater.UpdateSampleReaderCalls(content);
    updated = TestUpdater.UpdateTemplateNameAssertions(updated, migrationResult.TemplateNameMap);

    if (content != updated)
    {
        File.WriteAllText(testFile, updated);
        Console.WriteLine($"Updated: {testFile}");
    }
}
```

Note: In practice, the migration and test update should be run as a single operation. The `Program.cs` should serialize the `TemplateNameMap` to a JSON file during migration, and the `update-tests` mode should load it. This avoids re-running the migration.

Run: `dotnet run --project tools/WhoisMigration -- . update-tests`

- [ ] **Step 11: Build the solution**

```bash
dotnet build Whois.sln
```

Expected: BUILD SUCCEEDED. If there are compile errors, they will be in parsing test files where the `SampleReader.Read` signature changed. Fix any files that the automated update missed.

- [ ] **Step 12: Run all tests**

```bash
dotnet test tests/Whois.Tests/Whois.Tests.csproj
```

Expected: ALL PASS. If tests fail:
1. Check that sample files were moved to the correct status subdirectories
2. Check that template front matter `name:` fields were updated correctly
3. Check that `TemplateName` assertions in tests match the new names
4. Fix any issues and re-run

- [ ] **Step 13: Commit all updates**

```bash
git add tests/Whois.Tests/SampleReader.cs
git add tests/Whois.Tests/Parsing/
git add tools/WhoisMigration/
git commit -m "refactor: update SampleReader and parsing tests for new directory structure"
```

- [ ] **Step 14: Final verification — clean build and full test run**

```bash
dotnet clean Whois.sln
dotnet build Whois.sln
dotnet test Whois.sln
```

Expected: ALL PASS across all test projects, all target frameworks.

- [ ] **Step 15: Verify ResourceReader still works (no code changes needed)**

Confirm that `ResourceReader.GetNames("whois.nic.tr")` still returns results with the new directory structure. The prefix matching uses `Whois.Resources.whois.nic.tr` which matches both old and new embedded resource names:

```bash
dotnet test tests/Whois.Tests/ --filter "Test_found"
```

Expected: PASS — the prefix-based enumeration in `ResourceReader.GetNames` finds templates at the new paths because adding subdirectories only adds more dot segments to the embedded resource names. The existing `<EmbeddedResource Include="Resources\**\*.txt" />` glob already includes all subdirectories.

---

## Post-Migration Notes

**What changed:**
- 337 template files moved from `{server}/{tld}/{StatusName}.txt` to `{server}/{tld}/{status}/{nn}.txt`
- 756 sample files moved from `{server}/{tld}/{variant}.txt` to `{server}/{tld}/{status}/{variant}.txt`
- Template front matter `name:` fields updated to match new paths
- `SampleReader.Read` now takes 4 parameters: `(server, tld, status, filename)`
- All ~200 parsing test classes updated

**What did NOT change:**
- `ResourceReader` — prefix-based enumeration works unchanged
- `WhoisParser` — template loading via `reader.GetNames(whoisServer)` works unchanged
- `WhoisParser.Parse` — tag-based matching works unchanged
- Template content (matching patterns) — unchanged
- `Whois.csproj` — `<EmbeddedResource Include="Resources\**\*.txt" />` glob already includes subdirectories

**Migration tool (`tools/WhoisMigration/`):** This is a one-time tool. It can be removed after migration is verified, or kept for reference. It will not be needed for Plans 2-4.
