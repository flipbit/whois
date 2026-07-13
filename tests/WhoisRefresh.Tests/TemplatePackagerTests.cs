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
