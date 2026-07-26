using Whois.Refresh.Domain;
using Xunit;

namespace Whois.Refresh.Tests;

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
        // Empty directory  -  no .txt files
        Assert.Throws<InvalidOperationException>(
            () => TemplatePackager.BuildManifest(_tempDir, "2026.07.13.1"));
    }

    [Fact]
    public void CreatePackage_ProducesZipWithTemplatesAndManifest()
    {
        WriteTemplate("whois.nic.uk/uk/found/01.txt", "template content");
        var outputDir = Path.Combine(_tempDir, "output");

        var zipPath = TemplatePackager.CreatePackage(_tempDir, "2026.07.13.1", outputDir);

        Assert.True(File.Exists(zipPath));
        Assert.Equal(Path.Combine(outputDir, "templates.zip"), zipPath);

        using var archive = System.IO.Compression.ZipFile.OpenRead(zipPath);
        var entryNames = archive.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal).ToList();
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

        var manifest = Whois.Templates.TemplateManifest.Deserialize(File.ReadAllText(manifestPath));
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
            Assert.False(entry.FullName.StartsWith('/'), $"Entry path starts with /: {entry.FullName}");
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
            if (string.Equals(entry.FullName, "manifest.json", StringComparison.Ordinal)) continue;
            using var stream = entry.Open();
            using var entryMs = new MemoryStream();
            stream.CopyTo(entryMs);
            var hash = TemplatePackager.ComputeSha256Hex(entryMs.ToArray());
            hashes[entry.FullName] = hash;
        }

        var concatenated = string.Concat(hashes.Values);
        var expectedHash = TemplatePackager.ComputeSha256Hex(
            System.Text.Encoding.UTF8.GetBytes(concatenated));

        var manifest = Whois.Templates.TemplateManifest.Deserialize(
            File.ReadAllText(Path.Combine(outputDir, "manifest.json")));

        Assert.Equal(expectedHash, manifest.ContentHash);
    }
}
