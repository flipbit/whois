# Release Pipeline & GitHub Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package, sign, and publish versioned template packs as GitHub releases, plus a weekly automated refresh workflow.

**Architecture:** A new `package` command in the WhoisRefresh tool builds zip + manifest, a `ChangelogGenerator` diffs two manifests to produce changelogs, and two GitHub Action workflows orchestrate the release pipeline and weekly refresh. All meaningful logic lives in testable .NET code; workflows are thin shell orchestration.

**Tech Stack:** .NET 10, Spectre.Console.Cli, System.IO.Compression, System.Security.Cryptography (SHA-256), xUnit, NSubstitute, GitHub Actions, minisign CLI

## Global Constraints

- Target framework for WhoisRefresh tool: `net10.0`
- All types in `tools/WhoisRefresh/` (not in the library project)
- Use existing `TemplateManifest` / `TemplateEntry` from `src/Whois/Templates/` via project reference
- Content hash algorithm: sort template paths ascending by `StringComparer.Ordinal`, concatenate lowercase hex SHA-256 per file with no separator, SHA-256 the resulting UTF-8 string, encode as lowercase hex
- Exit codes: 0 = success, 1 = failure
- Follow existing test patterns in `tests/WhoisRefresh.Tests/` (xUnit, NSubstitute)
- TDD: write failing test first, then implement
- Commit after each task

---

### Task 1: TemplatePackager — Core Hashing and Manifest Generation

**Files:**
- Create: `tools/WhoisRefresh/Domain/TemplatePackager.cs`
- Test: `tests/WhoisRefresh.Tests/TemplatePackagerTests.cs`

**Interfaces:**
- Consumes: `TemplateManifest`, `TemplateEntry` from `Whois.Templates`
- Produces: `TemplatePackager.BuildManifest(string resourcesDir, string version)` → `TemplateManifest`

- [ ] **Step 1: Write the failing tests**

```csharp
// tests/WhoisRefresh.Tests/TemplatePackagerTests.cs
using System.Text.Json;
using Whois.Templates;
using WhoisRefresh.Domain;
using Xunit;

namespace WhoisRefresh.Tests;

public class TemplatePackagerTests : IDisposable
{
    private readonly string _tempDir;

    public TemplatePackagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"packager-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private void WriteTemplate(string relativePath, string content)
    {
        var fullPath = Path.Combine(_tempDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content);
    }

    [Fact]
    public void BuildManifest_ReturnsCorrectTemplateCount()
    {
        WriteTemplate("whois.nic.uk/uk/found/01.txt", "template content 1");
        WriteTemplate("whois.nic.uk/uk/not-found/01.txt", "template content 2");

        var manifest = TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1");

        Assert.Equal(2, manifest.TemplateCount);
        Assert.Equal(2, manifest.Templates.Count);
    }

    [Fact]
    public void BuildManifest_SetsVersionFromArgument()
    {
        WriteTemplate("whois.nic.uk/uk/found/01.txt", "content");

        var manifest = TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1");

        Assert.Equal("2026.07.13.1", manifest.Version);
    }

    [Fact]
    public void BuildManifest_ComputesPerFileHash()
    {
        WriteTemplate("whois.nic.uk/uk/found/01.txt", "hello world");

        var manifest = TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1");

        var entry = Assert.Single(manifest.Templates);
        Assert.Equal("whois.nic.uk/uk/found/01.txt", entry.Path);
        // SHA-256 of "hello world" bytes
        Assert.NotEmpty(entry.Hash);
        Assert.Matches("^[0-9a-f]{64}$", entry.Hash);
    }

    [Fact]
    public void BuildManifest_ContentHash_IsDeterministicRegardlessOfInsertionOrder()
    {
        WriteTemplate("b/tld/found/01.txt", "content b");
        WriteTemplate("a/tld/found/01.txt", "content a");

        var manifest1 = TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1");

        // Recreate in reverse file system order
        Directory.Delete(_tempDir, recursive: true);
        Directory.CreateDirectory(_tempDir);
        WriteTemplate("a/tld/found/01.txt", "content a");
        WriteTemplate("b/tld/found/01.txt", "content b");

        var manifest2 = TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1");

        Assert.Equal(manifest1.ContentHash, manifest2.ContentHash);
        Assert.Matches("^[0-9a-f]{64}$", manifest1.ContentHash);
    }

    [Fact]
    public void BuildManifest_TemplatesAreSortedByPathOrdinal()
    {
        WriteTemplate("z-server/tld/found/01.txt", "z");
        WriteTemplate("a-server/tld/found/01.txt", "a");
        WriteTemplate("m-server/tld/found/01.txt", "m");

        var manifest = TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1");

        Assert.Equal("a-server/tld/found/01.txt", manifest.Templates[0].Path);
        Assert.Equal("m-server/tld/found/01.txt", manifest.Templates[1].Path);
        Assert.Equal("z-server/tld/found/01.txt", manifest.Templates[2].Path);
    }

    [Fact]
    public void BuildManifest_ThrowsWhenDirectoryDoesNotExist()
    {
        Assert.Throws<DirectoryNotFoundException>(
            () => TemplatePackager.BuildManifest("/nonexistent/path", "2026.07.13.1"));
    }

    [Fact]
    public void BuildManifest_ThrowsWhenNoTemplatesFound()
    {
        // Empty directory — no .txt files
        Assert.Throws<InvalidOperationException>(
            () => TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~TemplatePackagerTests" --verbosity quiet`
Expected: FAIL — `TemplatePackager` does not exist

- [ ] **Step 3: Implement TemplatePackager.BuildManifest**

```csharp
// tools/WhoisRefresh/Domain/TemplatePackager.cs
using System.Security.Cryptography;
using System.Text;
using Whois.Templates;

namespace WhoisRefresh.Domain;

public static class TemplatePackager
{
    /// <summary>
    /// Enumerates template files, computes per-file and overall content hashes,
    /// and returns a populated <see cref="TemplateManifest"/>.
    /// </summary>
    /// <param name="resourcesDir">Path to the directory containing template files (e.g. src/Whois/Resources).</param>
    /// <param name="version">CalVer version string (e.g. "2026.07.13.1").</param>
    /// <exception cref="DirectoryNotFoundException">The directory does not exist.</exception>
    /// <exception cref="InvalidOperationException">No .txt files found.</exception>
    public static TemplateManifest BuildManifest(string resourcesDir, string version)
    {
        if (!Directory.Exists(resourcesDir))
            throw new DirectoryNotFoundException($"Template directory not found: {resourcesDir}");

        var templateFiles = Directory.GetFiles(resourcesDir, "*.txt", SearchOption.AllDirectories);
        if (templateFiles.Length == 0)
            throw new InvalidOperationException($"No template files found in: {resourcesDir}");

        var entries = new List<TemplateEntry>(templateFiles.Length);

        foreach (var file in templateFiles)
        {
            var relativePath = Path.GetRelativePath(resourcesDir, file)
                .Replace('\\', '/'); // Normalise to forward slashes

            var fileBytes = File.ReadAllBytes(file);
            var hash = ComputeSha256Hex(fileBytes);

            entries.Add(new TemplateEntry { Path = relativePath, Hash = hash });
        }

        // Sort by path using ordinal comparison for deterministic ordering
        entries.Sort((a, b) => string.Compare(a.Path, b.Path, StringComparison.Ordinal));

        // Content hash: concat all hashes in sorted order, then SHA-256 that string
        var concatenated = string.Concat(entries.Select(e => e.Hash));
        var contentHash = ComputeSha256Hex(Encoding.UTF8.GetBytes(concatenated));

        return new TemplateManifest
        {
            Version = version,
            ContentHash = contentHash,
            TemplateCount = entries.Count,
            Templates = entries,
        };
    }

    internal static string ComputeSha256Hex(byte[] data)
    {
        var hashBytes = SHA256.HashData(data);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~TemplatePackagerTests" --verbosity quiet`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tools/WhoisRefresh/Domain/TemplatePackager.cs tests/WhoisRefresh.Tests/TemplatePackagerTests.cs
git commit -m "feat: add TemplatePackager with manifest generation and content hashing"
```

---

### Task 2: TemplatePackager — Zip Creation

**Files:**
- Modify: `tools/WhoisRefresh/Domain/TemplatePackager.cs`
- Test: `tests/WhoisRefresh.Tests/TemplatePackagerTests.cs`

**Interfaces:**
- Consumes: `TemplatePackager.BuildManifest()` from Task 1
- Produces: `TemplatePackager.CreatePackage(string resourcesDir, string version, string outputDir)` → `string` (zip path)

- [ ] **Step 1: Write the failing tests**

Add to `TemplatePackagerTests.cs`:

```csharp
[Fact]
public void CreatePackage_ProducesZipWithTemplatesAndManifest()
{
    WriteTemplate("whois.nic.uk/uk/found/01.txt", "template content");
    var outputDir = Path.Combine(_tempDir, "output");

    var zipPath = TemplatePackager.CreatePackage(_tempDir, "2026.07.13.1", outputDir);

    Assert.True(File.Exists(zipPath));
    Assert.Equal(Path.Combine(outputDir, "templates.zip"), zipPath);

    using var archive = System.IO.Compression.ZipFile.OpenRead(zipPath);
    var entryNames = archive.Entries.Select(e => e.FullName).OrderBy(n => n, StringComparer.Ordinal).ToList();
    Assert.Contains("manifest.json", entryNames);
    Assert.Contains("whois.nic.uk/uk/found/01.txt", entryNames);
}

[Fact]
public void CreatePackage_WritesStandaloneManifestJson()
{
    WriteTemplate("whois.nic.uk/uk/found/01.txt", "content");
    var outputDir = Path.Combine(_tempDir, "output");

    TemplatePackager.CreatePackage(_tempDir, "2026.07.13.1", outputDir);

    var manifestPath = Path.Combine(outputDir, "manifest.json");
    Assert.True(File.Exists(manifestPath));

    var manifest = TemplateManifest.Deserialize(File.ReadAllText(manifestPath));
    Assert.Equal("2026.07.13.1", manifest.Version);
    Assert.Equal(1, manifest.TemplateCount);
}

[Fact]
public void CreatePackage_StandaloneManifest_MatchesZipManifest()
{
    WriteTemplate("whois.nic.uk/uk/found/01.txt", "content");
    var outputDir = Path.Combine(_tempDir, "output");

    TemplatePackager.CreatePackage(_tempDir, "2026.07.13.1", outputDir);

    var standaloneBytes = File.ReadAllBytes(Path.Combine(outputDir, "manifest.json"));

    using var archive = System.IO.Compression.ZipFile.OpenRead(Path.Combine(outputDir, "templates.zip"));
    var manifestEntry = archive.GetEntry("manifest.json")!;
    using var stream = manifestEntry.Open();
    using var ms = new MemoryStream();
    stream.CopyTo(ms);
    var zipManifestBytes = ms.ToArray();

    Assert.Equal(standaloneBytes, zipManifestBytes);
}

[Fact]
public void CreatePackage_ZipEntriesAreRelativeWithNoTraversal()
{
    WriteTemplate("whois.nic.uk/uk/found/01.txt", "content");
    WriteTemplate("generic/tld/found/01.txt", "content");
    var outputDir = Path.Combine(_tempDir, "output");

    TemplatePackager.CreatePackage(_tempDir, "2026.07.13.1", outputDir);

    using var archive = System.IO.Compression.ZipFile.OpenRead(Path.Combine(outputDir, "templates.zip"));
    foreach (var entry in archive.Entries)
    {
        Assert.DoesNotContain("..", entry.FullName);
        Assert.False(Path.IsPathRooted(entry.FullName), $"Entry path is absolute: {entry.FullName}");
        Assert.DoesNotStartWith("/", entry.FullName);
    }
}

[Fact]
public void CreatePackage_IntegrityCheck_RecomputedHashMatchesManifest()
{
    WriteTemplate("whois.nic.uk/uk/found/01.txt", "content 1");
    WriteTemplate("generic/tld/found/01.txt", "content 2");
    var outputDir = Path.Combine(_tempDir, "output");

    TemplatePackager.CreatePackage(_tempDir, "2026.07.13.1", outputDir);

    // Re-read templates from zip, recompute content hash
    using var archive = System.IO.Compression.ZipFile.OpenRead(Path.Combine(outputDir, "templates.zip"));
    var hashes = new SortedDictionary<string, string>(StringComparer.Ordinal);

    foreach (var entry in archive.Entries)
    {
        if (entry.FullName == "manifest.json") continue;
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        var hash = TemplatePackager.ComputeSha256Hex(ms.ToArray());
        hashes[entry.FullName] = hash;
    }

    var concatenated = string.Concat(hashes.Values);
    var expectedHash = TemplatePackager.ComputeSha256Hex(
        System.Text.Encoding.UTF8.GetBytes(concatenated));

    var manifest = TemplateManifest.Deserialize(
        File.ReadAllText(Path.Combine(outputDir, "manifest.json")));

    Assert.Equal(expectedHash, manifest.ContentHash);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~TemplatePackagerTests" --verbosity quiet`
Expected: 5 new tests FAIL — `CreatePackage` method does not exist

- [ ] **Step 3: Implement CreatePackage**

Add to `TemplatePackager.cs`:

```csharp
using System.IO.Compression;
using System.Text.Json;
```

Add method:

```csharp
/// <summary>
/// Builds the manifest and creates a zip containing all templates plus manifest.json.
/// Also writes a standalone manifest.json to the output directory (same bytes as in the zip).
/// </summary>
/// <returns>The path to the created zip file.</returns>
public static string CreatePackage(string resourcesDir, string version, string outputDir)
{
    var manifest = BuildManifest(resourcesDir, version);
    var manifestJson = JsonSerializer.Serialize(manifest, new JsonSerializerOptions
    {
        WriteIndented = true,
    });
    var manifestBytes = Encoding.UTF8.GetBytes(manifestJson);

    Directory.CreateDirectory(outputDir);

    var zipPath = Path.Combine(outputDir, "templates.zip");

    using (var zipStream = File.Create(zipPath))
    using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
    {
        // Add template files
        foreach (var entry in manifest.Templates)
        {
            var sourcePath = Path.Combine(resourcesDir, entry.Path.Replace('/', Path.DirectorySeparatorChar));
            var zipEntry = archive.CreateEntry(entry.Path, CompressionLevel.Optimal);
            using var entryStream = zipEntry.Open();
            using var fileStream = File.OpenRead(sourcePath);
            fileStream.CopyTo(entryStream);
        }

        // Add manifest.json
        var manifestEntry = archive.CreateEntry("manifest.json", CompressionLevel.Optimal);
        using var manifestStream = manifestEntry.Open();
        manifestStream.Write(manifestBytes, 0, manifestBytes.Length);
    }

    // Write standalone manifest (same bytes)
    File.WriteAllBytes(Path.Combine(outputDir, "manifest.json"), manifestBytes);

    return zipPath;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~TemplatePackagerTests" --verbosity quiet`
Expected: All 12 tests PASS

- [ ] **Step 5: Run full test suite**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --verbosity quiet`
Expected: All tests PASS (existing + new)

- [ ] **Step 6: Commit**

```bash
git add tools/WhoisRefresh/Domain/TemplatePackager.cs tests/WhoisRefresh.Tests/TemplatePackagerTests.cs
git commit -m "feat: add zip creation to TemplatePackager with integrity and security validation"
```

---

### Task 3: ChangelogGenerator

**Files:**
- Create: `tools/WhoisRefresh/Domain/ChangelogGenerator.cs`
- Test: `tests/WhoisRefresh.Tests/ChangelogGeneratorTests.cs`

**Interfaces:**
- Consumes: `TemplateManifest` from `Whois.Templates`
- Produces: `ChangelogGenerator.Generate(TemplateManifest current, TemplateManifest? previous)` → `ChangelogResult` with `.Json` and `.Markdown` properties

- [ ] **Step 1: Write the failing tests**

```csharp
// tests/WhoisRefresh.Tests/ChangelogGeneratorTests.cs
using System.Text.Json;
using Whois.Templates;
using WhoisRefresh.Domain;
using Xunit;

namespace WhoisRefresh.Tests;

public class ChangelogGeneratorTests
{
    private static TemplateManifest MakeManifest(string version, params (string path, string hash)[] templates)
    {
        var entries = templates.Select(t => new TemplateEntry { Path = t.path, Hash = t.hash }).ToList();
        return new TemplateManifest
        {
            Version = version,
            ContentHash = "ignored",
            TemplateCount = entries.Count,
            Templates = entries,
        };
    }

    [Fact]
    public void Generate_DetectsAddedTemplates()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("whois.nic.uk/uk/not-found/01.txt", "bbb"));

        var result = ChangelogGenerator.Generate(current, previous);

        Assert.Single(result.Added);
        Assert.Equal("whois.nic.uk/uk/not-found/01.txt", result.Added[0]);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Modified);
    }

    [Fact]
    public void Generate_DetectsRemovedTemplates()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("whois.nic.uk/uk/found/02.txt", "bbb"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(current, previous);

        Assert.Single(result.Removed);
        Assert.Equal("whois.nic.uk/uk/found/02.txt", result.Removed[0]);
    }

    [Fact]
    public void Generate_DetectsModifiedTemplates()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "bbb"));

        var result = ChangelogGenerator.Generate(current, previous);

        Assert.Single(result.Modified);
        Assert.Equal("whois.nic.uk/uk/found/01.txt", result.Modified[0]);
    }

    [Fact]
    public void Generate_IdenticalManifests_ProducesEmptyChangelog()
    {
        var manifest = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(manifest, manifest);

        Assert.Empty(result.Added);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Modified);
        Assert.False(result.HasChanges);
    }

    [Fact]
    public void Generate_NoPreviousManifest_AllTemplatesAreAdded()
    {
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("generic/tld/found/01.txt", "bbb"));

        var result = ChangelogGenerator.Generate(current, previous: null);

        Assert.Equal(2, result.Added.Count);
        Assert.Empty(result.Removed);
        Assert.Empty(result.Modified);
    }

    [Fact]
    public void ToJson_ProducesValidJson()
    {
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(current, previous: null);
        var json = result.ToJson();

        // Should parse without throwing
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("added", out _));
        Assert.True(doc.RootElement.TryGetProperty("removed", out _));
        Assert.True(doc.RootElement.TryGetProperty("modified", out _));
    }

    [Fact]
    public void ToMarkdown_ContainsSectionHeadings()
    {
        var previous = MakeManifest("2026.07.01.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"),
            ("old/tld/found/01.txt", "bbb"));
        var current = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "ccc"),
            ("new/tld/found/01.txt", "ddd"));

        var result = ChangelogGenerator.Generate(current, previous);
        var md = result.ToMarkdown();

        Assert.Contains("## Added", md);
        Assert.Contains("## Removed", md);
        Assert.Contains("## Modified", md);
        Assert.Contains("new/tld/found/01.txt", md);
        Assert.Contains("old/tld/found/01.txt", md);
        Assert.Contains("whois.nic.uk/uk/found/01.txt", md);
    }

    [Fact]
    public void ToMarkdown_EmptyChangelog_SaysNoChanges()
    {
        var manifest = MakeManifest("2026.07.13.1",
            ("whois.nic.uk/uk/found/01.txt", "aaa"));

        var result = ChangelogGenerator.Generate(manifest, manifest);
        var md = result.ToMarkdown();

        Assert.Contains("No changes", md);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~ChangelogGeneratorTests" --verbosity quiet`
Expected: FAIL — `ChangelogGenerator` does not exist

- [ ] **Step 3: Implement ChangelogGenerator**

```csharp
// tools/WhoisRefresh/Domain/ChangelogGenerator.cs
using System.Text;
using System.Text.Json;
using Whois.Templates;

namespace WhoisRefresh.Domain;

public sealed class ChangelogResult
{
    public IList<string> Added { get; init; } = new List<string>();
    public IList<string> Removed { get; init; } = new List<string>();
    public IList<string> Modified { get; init; } = new List<string>();
    public bool HasChanges => Added.Count > 0 || Removed.Count > 0 || Modified.Count > 0;

    public string ToJson()
    {
        return JsonSerializer.Serialize(new
        {
            added = Added,
            removed = Removed,
            modified = Modified,
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    public string ToMarkdown()
    {
        if (!HasChanges)
            return "No changes detected.\n";

        var sb = new StringBuilder();
        sb.AppendLine("# Template Changelog");
        sb.AppendLine();

        if (Added.Count > 0)
        {
            sb.AppendLine("## Added");
            sb.AppendLine();
            foreach (var path in Added)
                sb.AppendLine($"- `{path}`");
            sb.AppendLine();
        }

        if (Removed.Count > 0)
        {
            sb.AppendLine("## Removed");
            sb.AppendLine();
            foreach (var path in Removed)
                sb.AppendLine($"- `{path}`");
            sb.AppendLine();
        }

        if (Modified.Count > 0)
        {
            sb.AppendLine("## Modified");
            sb.AppendLine();
            foreach (var path in Modified)
                sb.AppendLine($"- `{path}`");
            sb.AppendLine();
        }

        return sb.ToString();
    }
}

public static class ChangelogGenerator
{
    /// <summary>
    /// Diffs two manifests by comparing per-template hashes.
    /// </summary>
    /// <param name="current">The new manifest.</param>
    /// <param name="previous">The previous manifest, or null for a first release.</param>
    public static ChangelogResult Generate(TemplateManifest current, TemplateManifest? previous)
    {
        var currentMap = current.Templates.ToDictionary(t => t.Path, t => t.Hash, StringComparer.Ordinal);
        var previousMap = previous?.Templates.ToDictionary(t => t.Path, t => t.Hash, StringComparer.Ordinal)
            ?? new Dictionary<string, string>(StringComparer.Ordinal);

        var added = new List<string>();
        var removed = new List<string>();
        var modified = new List<string>();

        foreach (var (path, hash) in currentMap)
        {
            if (!previousMap.TryGetValue(path, out var prevHash))
                added.Add(path);
            else if (!string.Equals(hash, prevHash, StringComparison.Ordinal))
                modified.Add(path);
        }

        foreach (var path in previousMap.Keys)
        {
            if (!currentMap.ContainsKey(path))
                removed.Add(path);
        }

        added.Sort(StringComparer.Ordinal);
        removed.Sort(StringComparer.Ordinal);
        modified.Sort(StringComparer.Ordinal);

        return new ChangelogResult
        {
            Added = added,
            Removed = removed,
            Modified = modified,
        };
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~ChangelogGeneratorTests" --verbosity quiet`
Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tools/WhoisRefresh/Domain/ChangelogGenerator.cs tests/WhoisRefresh.Tests/ChangelogGeneratorTests.cs
git commit -m "feat: add ChangelogGenerator with manifest-diff and JSON/markdown output"
```

---

### Task 4: PackageCommand — Spectre.Cli Integration

**Files:**
- Create: `tools/WhoisRefresh/Commands/PackageCommand.cs`
- Modify: `tools/WhoisRefresh/Program.cs`
- Test: `tests/WhoisRefresh.Tests/PackageCommandTests.cs`

**Interfaces:**
- Consumes: `TemplatePackager.CreatePackage()` from Task 2, `ChangelogGenerator.Generate()` from Task 3, `TemplateManifest.Deserialize()` from `Whois.Templates`
- Produces: `PackageCommand` — Spectre.Cli `AsyncCommand<PackageSettings>` registered as `package`

- [ ] **Step 1: Write the failing tests**

```csharp
// tests/WhoisRefresh.Tests/PackageCommandTests.cs
using System.IO.Compression;
using Whois.Templates;
using WhoisRefresh.Commands;
using WhoisRefresh.Domain;
using Xunit;

namespace WhoisRefresh.Tests;

public class PackageCommandTests : IDisposable
{
    private readonly string _repoRoot;
    private readonly string _outputDir;

    public PackageCommandTests()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), $"pkg-cmd-test-{Guid.NewGuid():N}");
        _repoRoot = baseDir;
        _outputDir = Path.Combine(baseDir, "artifacts");

        // Create a minimal repo structure with templates
        var resourcesDir = Path.Combine(_repoRoot, "src", "Whois", "Resources");
        Directory.CreateDirectory(Path.Combine(resourcesDir, "whois.nic.uk", "uk", "found"));
        File.WriteAllText(
            Path.Combine(resourcesDir, "whois.nic.uk", "uk", "found", "01.txt"),
            "template content");
    }

    public void Dispose()
    {
        if (Directory.Exists(_repoRoot))
            Directory.Delete(_repoRoot, recursive: true);
    }

    [Fact]
    public void Execute_Success_ProducesAllArtifacts()
    {
        var exitCode = PackageCommand.Run(_repoRoot, "2026.07.13.1", previousManifestPath: null, _outputDir);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(Path.Combine(_outputDir, "templates.zip")));
        Assert.True(File.Exists(Path.Combine(_outputDir, "manifest.json")));
        // No previous manifest → no changelog
        Assert.False(File.Exists(Path.Combine(_outputDir, "changelog.json")));
        Assert.False(File.Exists(Path.Combine(_outputDir, "changelog.md")));
    }

    [Fact]
    public void Execute_WithPreviousManifest_ProducesChangelog()
    {
        // First, create a "previous" manifest
        var prevDir = Path.Combine(_repoRoot, "previous");
        Directory.CreateDirectory(prevDir);
        var prevManifest = new TemplateManifest
        {
            Version = "2026.07.01.1",
            ContentHash = "old",
            TemplateCount = 0,
            Templates = new List<TemplateEntry>(),
        };
        File.WriteAllText(
            Path.Combine(prevDir, "manifest.json"),
            System.Text.Json.JsonSerializer.Serialize(prevManifest));

        var exitCode = PackageCommand.Run(
            _repoRoot, "2026.07.13.1",
            Path.Combine(prevDir, "manifest.json"), _outputDir);

        Assert.Equal(0, exitCode);
        Assert.True(File.Exists(Path.Combine(_outputDir, "changelog.json")));
        Assert.True(File.Exists(Path.Combine(_outputDir, "changelog.md")));
    }

    [Fact]
    public void Execute_MissingTemplatesDir_ReturnsNonZero()
    {
        var emptyRoot = Path.Combine(Path.GetTempPath(), $"empty-{Guid.NewGuid():N}");
        Directory.CreateDirectory(emptyRoot);

        try
        {
            var exitCode = PackageCommand.Run(emptyRoot, "2026.07.13.1", null, _outputDir);
            Assert.Equal(1, exitCode);
        }
        finally
        {
            Directory.Delete(emptyRoot, recursive: true);
        }
    }

    [Fact]
    public void Execute_PreviousManifestNotFound_ReturnsNonZero()
    {
        var exitCode = PackageCommand.Run(
            _repoRoot, "2026.07.13.1",
            "/nonexistent/manifest.json", _outputDir);

        Assert.Equal(1, exitCode);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~PackageCommandTests" --verbosity quiet`
Expected: FAIL — `PackageCommand` does not exist

- [ ] **Step 3: Implement PackageCommand**

```csharp
// tools/WhoisRefresh/Commands/PackageCommand.cs
using Spectre.Console;
using Spectre.Console.Cli;
using Whois.Templates;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Commands;

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
                catch (Exception ex)
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

            if (isCi)
            {
                Console.WriteLine($"::notice::Package created: {manifest.TemplateCount} templates, " +
                    $"version {manifest.Version}, content hash {manifest.ContentHash}");
            }
            else
            {
                AnsiConsole.MarkupLine(
                    $"[green]Package created:[/] {manifest.TemplateCount} templates, " +
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
```

- [ ] **Step 4: Register the command in Program.cs**

Add to `Program.cs` inside the `app.Configure` block:

```csharp
config.AddCommand<PackageCommand>("package")
    .WithDescription("Build a versioned template pack zip with manifest");
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~PackageCommandTests" --verbosity quiet`
Expected: All 4 tests PASS

- [ ] **Step 6: Run full test suite**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --verbosity quiet && dotnet test tests/Whois.Tests/Whois.Tests.csproj --verbosity quiet`
Expected: All tests PASS in both projects

- [ ] **Step 7: Commit**

```bash
git add tools/WhoisRefresh/Commands/PackageCommand.cs tools/WhoisRefresh/Program.cs tests/WhoisRefresh.Tests/PackageCommandTests.cs
git commit -m "feat: add package command with Spectre.Cli integration, CI output, and exit codes"
```

---

### Task 5: Minisign Round-Trip Tests and Production Key

**Files:**
- Create: `tests/WhoisRefresh.Tests/MinisignRoundTripTests.cs`
- Modify: `src/Whois/Templates/TemplatePackProvider.cs` (replace `EmbeddedPublicKey`)

**Interfaces:**
- Consumes: `MinisignVerifier.Verify()` from `Whois.Security`
- Produces: Production public key constant, round-trip test validation

The round-trip test uses pre-generated test fixtures rather than calling the minisign CLI (which may not be available on all CI platforms, especially Windows). We generate a keypair and signature once during development, then embed the test data.

- [ ] **Step 1: Generate a production minisign keypair**

Run locally (not in CI):

```bash
# Install minisign if not already available
brew install minisign  # macOS

# Generate keypair — will prompt for a password. Use an empty password for the CI key.
minisign -G -p whois-templates.pub -s whois-templates.key -c "whois template signing key"
```

Record the public key content (two lines from `whois-templates.pub`) and the secret key content (from `whois-templates.key`). Store the secret key file securely — it will be added to GitHub Environment secrets later.

- [ ] **Step 2: Generate test fixtures for round-trip test**

```bash
# Create a small test payload
echo -n "test payload for signature verification" > /tmp/test-payload.bin

# Sign it with the production key
minisign -Sm /tmp/test-payload.bin -s whois-templates.key -t "test signature"

# Also generate a second keypair for the negative test
minisign -G -p /tmp/test-key-b.pub -s /tmp/test-key-b.key -c "test key B"
minisign -Sm /tmp/test-payload.bin -s /tmp/test-key-b.key -t "test signature B" -x /tmp/test-payload.bin.minisig.b
```

Read the contents of the generated files. You'll embed these as string constants in the test.

- [ ] **Step 3: Replace EmbeddedPublicKey in TemplatePackProvider.cs**

In `src/Whois/Templates/TemplatePackProvider.cs`, replace the test constant:

```csharp
// Replace this:
private const string EmbeddedPublicKey =
    "untrusted comment: minisign public key test\n" +
    "RWQBAgMEBQYHCNdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";

// With the actual public key from whois-templates.pub (two lines):
private const string EmbeddedPublicKey =
    "untrusted comment: whois template signing key\n" +
    "<BASE64_FROM_PUB_FILE>";
```

- [ ] **Step 4: Write the round-trip tests**

```csharp
// tests/WhoisRefresh.Tests/MinisignRoundTripTests.cs
using System.Text;
using Whois.Security;
using Xunit;

namespace WhoisRefresh.Tests;

public class MinisignRoundTripTests
{
    // These constants are generated during Plan 4 implementation (Step 2 above).
    // Replace with actual values from the generated files.

    private const string ProductionPublicKey =
        "untrusted comment: whois template signing key\n" +
        "<BASE64_FROM_PUB_FILE>";

    private const string TestPayload = "test payload for signature verification";

    // Signature generated by: minisign -Sm test-payload.bin -s whois-templates.key
    private const string ValidSignature =
        "untrusted comment: test signature\n" +
        "<BASE64_FROM_MINISIG_FILE>";

    // A different keypair's public key
    private const string DifferentPublicKey =
        "untrusted comment: test key B\n" +
        "<BASE64_FROM_TEST_KEY_B_PUB>";

    // Signature generated with the different key
    private const string DifferentKeySignature =
        "untrusted comment: test signature B\n" +
        "<BASE64_FROM_TEST_KEY_B_MINISIG>";

    [Fact]
    public void ProductionKey_VerifiesSignatureFromMinisignCli()
    {
        var content = Encoding.UTF8.GetBytes(TestPayload);

        var result = MinisignVerifier.Verify(content, ValidSignature, ProductionPublicKey);

        Assert.True(result, "Signature produced by minisign CLI should verify against production public key");
    }

    [Fact]
    public void ProductionKey_RejectsTamperedContent()
    {
        var tampered = Encoding.UTF8.GetBytes(TestPayload + " TAMPERED");

        var result = MinisignVerifier.Verify(tampered, ValidSignature, ProductionPublicKey);

        Assert.False(result, "Tampered content should fail verification");
    }

    [Fact]
    public void ProductionKey_RejectsSignatureFromDifferentKey()
    {
        var content = Encoding.UTF8.GetBytes(TestPayload);

        // Signature was generated with a different key — key IDs won't match
        var result = MinisignVerifier.Verify(content, DifferentKeySignature, ProductionPublicKey);

        Assert.False(result, "Signature from a different key must not verify against the production public key");
    }

    [Fact]
    public void DifferentKey_VerifiesItsOwnSignature()
    {
        var content = Encoding.UTF8.GetBytes(TestPayload);

        // Sanity check: the different key's signature verifies against its own public key
        var result = MinisignVerifier.Verify(content, DifferentKeySignature, DifferentPublicKey);

        Assert.True(result, "Signature should verify against the key that produced it");
    }
}
```

**Note:** The `<BASE64_...>` placeholders must be replaced with actual values from the files generated in Steps 1–2. These are one-time generated constants — the test data is deterministic.

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~MinisignRoundTripTests" --verbosity quiet`
Expected: All 4 tests PASS

- [ ] **Step 6: Run full library test suite to confirm key swap didn't break anything**

Run: `dotnet test tests/Whois.Tests/Whois.Tests.csproj --verbosity quiet`
Expected: All tests PASS (Plan 3 tests inject their own signatureVerifier, don't depend on EmbeddedPublicKey)

- [ ] **Step 7: Commit**

```bash
git add src/Whois/Templates/TemplatePackProvider.cs tests/WhoisRefresh.Tests/MinisignRoundTripTests.cs
git commit -m "feat: replace test keypair with production minisign key, add round-trip verification tests"
```

---

### Task 6: Template Release Workflow

**Files:**
- Create: `.github/workflows/whois-template-release.yml`

**Interfaces:**
- Consumes: `package` command from Task 4, `minisign` CLI, `gh` CLI
- Produces: GitHub releases with signed template packs

- [ ] **Step 1: Create the workflow file**

```yaml
# .github/workflows/whois-template-release.yml
name: Template Release

on:
  push:
    branches: [main]
    paths: ['src/Whois/Resources/**']

permissions: {}

jobs:
  release:
    runs-on: ubuntu-latest
    environment: template-release
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Install minisign
        run: sudo apt-get install -y minisign

      - name: Compute CalVer version
        id: version
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          TODAY=$(date -u +%Y.%m.%d)
          LATEST_TAG=$(gh release list --limit 10 --json tagName --jq '[.[] | select(.tagName | startswith("templates-"))][0].tagName // ""')

          if [ -n "$LATEST_TAG" ]; then
            LATEST_VERSION="${LATEST_TAG#templates-}"
            LATEST_DATE=$(echo "$LATEST_VERSION" | cut -d. -f1-3)
            LATEST_SEQ=$(echo "$LATEST_VERSION" | cut -d. -f4)
            if [ "$LATEST_DATE" = "$TODAY" ]; then
              SEQ=$((LATEST_SEQ + 1))
            else
              SEQ=1
            fi
          else
            SEQ=1
          fi

          VERSION="${TODAY}.${SEQ}"
          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          echo "latest_tag=$LATEST_TAG" >> "$GITHUB_OUTPUT"
          echo "::notice::Template pack version: $VERSION"

      - name: Download previous manifest
        if: steps.version.outputs.latest_tag != ''
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          mkdir -p ./previous
          gh release download "${{ steps.version.outputs.latest_tag }}" --pattern manifest.json -D ./previous || true

      - name: Build package
        run: |
          PREV_FLAG=""
          if [ -f ./previous/manifest.json ]; then
            PREV_FLAG="--previous-manifest ./previous/manifest.json"
          fi
          dotnet run --project tools/WhoisRefresh -- package . --version "${{ steps.version.outputs.version }}" $PREV_FLAG --output ./artifacts

      - name: Sign template pack
        env:
          MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
        run: |
          KEYFILE=$(mktemp)
          chmod 600 "$KEYFILE"
          trap 'rm -f "$KEYFILE"' EXIT
          echo "$MINISIGN_SECRET_KEY" > "$KEYFILE"
          minisign -Sm artifacts/templates.zip -s "$KEYFILE" -t "templates-${{ steps.version.outputs.version }}"

      - name: Create GitHub release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          VERSION="${{ steps.version.outputs.version }}"
          NOTES_FLAG=""
          if [ -f ./artifacts/changelog.md ]; then
            NOTES_FLAG="--notes-file ./artifacts/changelog.md"
          fi
          gh release create "templates-${VERSION}" \
            ./artifacts/templates.zip \
            ./artifacts/templates.zip.minisig \
            ./artifacts/manifest.json \
            --title "Templates ${VERSION}" \
            $NOTES_FLAG
```

- [ ] **Step 2: Validate the workflow file syntax**

Run: `cat .github/workflows/whois-template-release.yml | head -5`
Expected: The file exists and starts with `name: Template Release`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/whois-template-release.yml
git commit -m "feat: add template release workflow with CalVer, signing, and changelog"
```

---

### Task 7: Weekly Refresh Workflow

**Files:**
- Create: `.github/workflows/whois-refresh.yml`

**Interfaces:**
- Consumes: `refresh` and `detect` commands from WhoisRefresh tool, `gh` CLI
- Produces: Automated weekly refresh with drift PR management and staleness alerts

- [ ] **Step 1: Create the workflow file**

```yaml
# .github/workflows/whois-refresh.yml
name: Weekly WHOIS Refresh

on:
  schedule:
    - cron: '0 2 * * 0'  # Sunday 02:00 UTC
  workflow_dispatch:

permissions: {}

jobs:
  refresh:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: write
      pull-requests: write
      issues: write

    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Staleness check
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          RESULTS_FILE="tools/WhoisRefresh/refresh-results.json"
          if [ ! -f "$RESULTS_FILE" ]; then
            echo "::warning::No refresh-results.json baseline found"
            exit 0
          fi

          # Extract the version timestamp
          LAST_RUN=$(python3 -c "
          import json, sys
          with open('$RESULTS_FILE') as f:
              data = json.load(f)
          print(data.get('version', ''))
          ")

          if [ -z "$LAST_RUN" ]; then
            echo "::warning::Could not read version timestamp from refresh-results.json"
            exit 0
          fi

          # Check if older than 28 days
          LAST_EPOCH=$(date -d "$LAST_RUN" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${LAST_RUN%%.*}" +%s 2>/dev/null || echo 0)
          NOW_EPOCH=$(date +%s)
          DAYS_OLD=$(( (NOW_EPOCH - LAST_EPOCH) / 86400 ))

          if [ "$DAYS_OLD" -ge 28 ]; then
            echo "::warning::Refresh baseline is ${DAYS_OLD} days old (threshold: 28 days)"

            # Check for existing staleness issue
            EXISTING=$(gh issue list --label "staleness-alert" --state open --json number --jq '.[0].number // ""')
            if [ -z "$EXISTING" ]; then
              gh issue create \
                --title "WHOIS refresh baseline is stale (${DAYS_OLD} days)" \
                --label "staleness-alert" \
                --body "The refresh-results.json baseline has not been updated in ${DAYS_OLD} days. The last successful run was at ${LAST_RUN}. Please investigate why the weekly refresh workflow has not been running successfully."
              echo "::notice::Staleness issue created"
            else
              echo "::notice::Staleness issue already exists (#${EXISTING})"
            fi
          else
            echo "::notice::Baseline is ${DAYS_OLD} days old (within 28-day threshold)"
          fi

      - name: Run refresh
        run: dotnet run --project tools/WhoisRefresh -- refresh .

      - name: Run detect
        id: detect
        run: |
          dotnet run --project tools/WhoisRefresh -- detect .
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"
        continue-on-error: true

      - name: Handle results
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          DETECT_EXIT="${{ steps.detect.outcome == 'failure' && '1' || '0' }}"

          # Check if there are any changes
          if git diff --quiet && git diff --cached --quiet; then
            echo "::notice::No changes detected"
            exit 0
          fi

          BRANCH_DATE=$(date -u +%Y-%m-%d)

          if [ "$DETECT_EXIT" = "1" ]; then
            # Breakages found — use template-drift branch
            BRANCH="template-drift"

            # Check if template-drift has human commits
            if git rev-parse --verify "origin/${BRANCH}" >/dev/null 2>&1; then
              HUMAN_COMMITS=$(git log "origin/main..origin/${BRANCH}" --format="%ae" | grep -v "github-actions" | head -1 || true)
              if [ -n "$HUMAN_COMMITS" ]; then
                BRANCH="template-drift/${BRANCH_DATE}"
                echo "::notice::Using dated branch ${BRANCH} to avoid overwriting human work"
              fi
            fi

            git checkout -B "$BRANCH"
            git add tools/WhoisRefresh/refresh-results.json tests/Whois.Tests/Samples/ tools/WhoisRefresh/drift-report.json tools/WhoisRefresh/drift-report.md
            git commit -m "chore: update refresh results and drift report (${BRANCH_DATE})" || true

            git push -u origin "$BRANCH" --force-with-lease

            # Check for existing PR
            EXISTING_PR=$(gh pr list --head "$BRANCH" --json number --jq '.[0].number // ""')
            BODY_FILE="tools/WhoisRefresh/drift-report.md"

            if [ -n "$EXISTING_PR" ]; then
              gh pr edit "$EXISTING_PR" --body-file "$BODY_FILE"
              echo "::notice::Updated existing drift PR #${EXISTING_PR}"
            else
              gh pr create \
                --head "$BRANCH" \
                --title "Template drift detected (${BRANCH_DATE})" \
                --body-file "$BODY_FILE" \
                --label "template-drift"
              echo "::notice::Created new drift PR"
            fi
          else
            # No breakages, but samples changed
            BRANCH="refresh/${BRANCH_DATE}"
            git checkout -B "$BRANCH"
            git add tools/WhoisRefresh/refresh-results.json tests/Whois.Tests/Samples/
            git commit -m "chore: update WHOIS samples (${BRANCH_DATE})" || true
            git push -u origin "$BRANCH"

            gh pr create \
              --head "$BRANCH" \
              --title "WHOIS sample refresh (${BRANCH_DATE})" \
              --body "Automated weekly refresh — no breakages detected. Updated samples and baseline." \
              --label "refresh"
            echo "::notice::Created refresh PR on branch ${BRANCH}"
          fi
```

- [ ] **Step 2: Validate the workflow file syntax**

Run: `cat .github/workflows/whois-refresh.yml | head -5`
Expected: The file exists and starts with `name: Weekly WHOIS Refresh`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/whois-refresh.yml
git commit -m "feat: add weekly WHOIS refresh workflow with staleness alerts and drift PR management"
```

---

### Task 8: End-to-End Integration Test

**Files:**
- Modify: `tests/WhoisRefresh.Tests/PackageCommandTests.cs`

**Interfaces:**
- Consumes: all components from Tasks 1–4

This task adds the end-to-end test that verifies the complete pipeline: packaging with a previous manifest, verifying the zip can be consumed by the client-side `TemplateManifest.Deserialize`, and re-verifying content hash integrity.

- [ ] **Step 1: Write the integration test**

Add to `PackageCommandTests.cs`:

```csharp
[Fact]
public void EndToEnd_PackageThenDiff_ProducesValidArtifacts()
{
    // First release — no previous manifest
    var exitCode1 = PackageCommand.Run(_repoRoot, "2026.07.01.1", null, _outputDir);
    Assert.Equal(0, exitCode1);

    // Read the manifest from the first release
    var firstManifestPath = Path.Combine(_outputDir, "manifest.json");
    var firstManifest = TemplateManifest.Deserialize(File.ReadAllText(firstManifestPath));
    Assert.Equal("2026.07.01.1", firstManifest.Version);
    Assert.Equal(1, firstManifest.TemplateCount);

    // Modify a template and add a new one
    var resourcesDir = Path.Combine(_repoRoot, "src", "Whois", "Resources");
    File.WriteAllText(
        Path.Combine(resourcesDir, "whois.nic.uk", "uk", "found", "01.txt"),
        "modified template content");
    Directory.CreateDirectory(Path.Combine(resourcesDir, "generic", "tld", "found"));
    File.WriteAllText(
        Path.Combine(resourcesDir, "generic", "tld", "found", "01.txt"),
        "new generic template");

    // Save first manifest as "previous"
    var prevDir = Path.Combine(_repoRoot, "previous");
    Directory.CreateDirectory(prevDir);
    File.Copy(firstManifestPath, Path.Combine(prevDir, "manifest.json"));

    // Clean output for second release
    Directory.Delete(_outputDir, recursive: true);

    // Second release with previous manifest
    var exitCode2 = PackageCommand.Run(
        _repoRoot, "2026.07.13.1",
        Path.Combine(prevDir, "manifest.json"), _outputDir);
    Assert.Equal(0, exitCode2);

    // Verify changelog was produced
    var changelogJson = File.ReadAllText(Path.Combine(_outputDir, "changelog.json"));
    using var doc = System.Text.Json.JsonDocument.Parse(changelogJson);
    var root = doc.RootElement;

    var added = root.GetProperty("added").EnumerateArray().Select(e => e.GetString()).ToList();
    var modified = root.GetProperty("modified").EnumerateArray().Select(e => e.GetString()).ToList();

    Assert.Contains("generic/tld/found/01.txt", added);
    Assert.Contains("whois.nic.uk/uk/found/01.txt", modified);

    // Verify the zip is valid and manifest deserializes
    var secondManifest = TemplateManifest.Deserialize(
        File.ReadAllText(Path.Combine(_outputDir, "manifest.json")));
    Assert.Equal("2026.07.13.1", secondManifest.Version);
    Assert.Equal(2, secondManifest.TemplateCount);

    // Verify content hash changed
    Assert.NotEqual(firstManifest.ContentHash, secondManifest.ContentHash);
}
```

- [ ] **Step 2: Run the test**

Run: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj --filter "FullyQualifiedName~EndToEnd_PackageThenDiff" --verbosity quiet`
Expected: PASS

- [ ] **Step 3: Run the full test suite**

Run: `dotnet test Whois.sln --verbosity quiet`
Expected: All tests PASS across all projects

- [ ] **Step 4: Commit**

```bash
git add tests/WhoisRefresh.Tests/PackageCommandTests.cs
git commit -m "test: add end-to-end integration test for package-then-diff pipeline"
```
