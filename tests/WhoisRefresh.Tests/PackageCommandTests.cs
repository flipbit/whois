using Whois.Templates;
using WhoisRefresh.Commands;
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
