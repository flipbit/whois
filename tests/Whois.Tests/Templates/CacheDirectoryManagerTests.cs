using System.Globalization;
using System.IO.Compression;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Whois.Templates;

namespace Whois.Tests.Templates;

/// <summary>
/// Tests for CacheDirectoryManager using real temp directories.
/// All tests clean up after themselves in Dispose.
/// </summary>
public class CacheDirectoryManagerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CacheDirectoryManager _manager;

    public CacheDirectoryManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "whois-cache-tests-" + Guid.NewGuid().ToString("N"));
        _manager = new CacheDirectoryManager(_tempDir, NullLogger<CacheDirectoryManager>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    // -------------------------------------------------------------------------
    // EnsureDirectory
    // -------------------------------------------------------------------------

    [Fact]
    public void EnsureDirectory_CreatesDirectory()
    {
        Assert.False(Directory.Exists(_tempDir));

        var result = _manager.EnsureDirectory();

        Assert.True(result);
        Assert.True(Directory.Exists(_tempDir));
    }

    [Fact]
    public void EnsureDirectory_DirectoryAlreadyExists_ReturnsTrue()
    {
        Directory.CreateDirectory(_tempDir);

        var result = _manager.EnsureDirectory();

        Assert.True(result);
        Assert.True(Directory.Exists(_tempDir));
    }

    [Fact]
    public void EnsureDirectory_InvalidPath_ReturnsFalse()
    {
        // Null chars are invalid on all platforms
        var badDir = _tempDir + "\0invalid";
        var manager = new CacheDirectoryManager(badDir, NullLogger<CacheDirectoryManager>.Instance);

        var result = manager.EnsureDirectory();

        Assert.False(result);
    }

    // -------------------------------------------------------------------------
    // ExtractPack
    // -------------------------------------------------------------------------

    [Fact]
    public void ExtractPack_ValidZip_ExtractsFiles()
    {
        Directory.CreateDirectory(_tempDir);
        var zip = BuildZip(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["whois.nic.uk/uk/found/01.txt"] = "Domain found template",
            ["whois.nic.uk/uk/notfound/01.txt"] = "Domain not found template",
        });

        var result = _manager.ExtractPack(zip, "current");

        Assert.True(result);
        var file1 = Path.Combine(_tempDir, "current", "whois.nic.uk", "uk", "found", "01.txt");
        var file2 = Path.Combine(_tempDir, "current", "whois.nic.uk", "uk", "notfound", "01.txt");
        Assert.True(File.Exists(file1));
        Assert.True(File.Exists(file2));
        Assert.Equal("Domain found template", File.ReadAllText(file1));
    }

    [Fact]
    public void ExtractPack_ZipSlipEntry_Rejects()
    {
        Directory.CreateDirectory(_tempDir);
        var zip = BuildZip(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["../outside.txt"] = "should not be extracted",
        });

        var result = _manager.ExtractPack(zip, "current");

        Assert.False(result);
        // Cleanup: target directory should not remain
        Assert.False(Directory.Exists(Path.Combine(_tempDir, "current")));
    }

    [Fact]
    public void ExtractPack_NormalisedTraversal_Rejects()
    {
        Directory.CreateDirectory(_tempDir);
        // foo/../../bar normalises to ../bar which escapes the target
        var zip = BuildZip(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["foo/../../bar.txt"] = "should not be extracted",
        });

        var result = _manager.ExtractPack(zip, "current");

        Assert.False(result);
        Assert.False(Directory.Exists(Path.Combine(_tempDir, "current")));
    }

    [Fact]
    public void ExtractPack_AbsolutePath_Rejects()
    {
        Directory.CreateDirectory(_tempDir);
        // Use a Unix-style absolute path — ZipArchive will store the entry name as-is
        var zip = BuildZipRawEntry("/etc/passwd", "should not be extracted");

        var result = _manager.ExtractPack(zip, "current");

        Assert.False(result);
        Assert.False(Directory.Exists(Path.Combine(_tempDir, "current")));
    }

    [Fact]
    public void ExtractPack_ExceedsSizeCap_Rejects()
    {
        Directory.CreateDirectory(_tempDir);
        // Each entry is ~10MB; 6 entries = ~60MB > 50MB cap
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < 6; i++)
            entries[string.Format(CultureInfo.InvariantCulture, "file{0}.txt", i)] = new string('x', 10 * 1024 * 1024);

        var zip = BuildZip(entries);

        var result = _manager.ExtractPack(zip, "current");

        Assert.False(result);
        Assert.False(Directory.Exists(Path.Combine(_tempDir, "current")));
    }

    [Fact]
    public void ExtractPack_ExceedsEntryCap_Rejects()
    {
        Directory.CreateDirectory(_tempDir);
        // 10,001 entries > 10,000 cap
        var entries = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < 10_001; i++)
            entries[string.Format(CultureInfo.InvariantCulture, "file{0:D5}.txt", i)] = "x";

        var zip = BuildZip(entries);

        var result = _manager.ExtractPack(zip, "current");

        Assert.False(result);
        Assert.False(Directory.Exists(Path.Combine(_tempDir, "current")));
    }

    [Fact]
    public void ExtractPack_CleansUpOnFailure()
    {
        Directory.CreateDirectory(_tempDir);
        // Pre-create target to ensure it gets cleaned up
        Directory.CreateDirectory(Path.Combine(_tempDir, "current"));

        var zip = BuildZip(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["../escape.txt"] = "bad",
        });

        var result = _manager.ExtractPack(zip, "current");

        Assert.False(result);
        Assert.False(Directory.Exists(Path.Combine(_tempDir, "current")));
    }

    // -------------------------------------------------------------------------
    // WriteFile / ReadFile
    // -------------------------------------------------------------------------

    [Fact]
    public void WriteFile_AtomicWrite_Succeeds()
    {
        Directory.CreateDirectory(_tempDir);
        var content = new byte[] { 0x01, 0x02, 0x03, 0xFF };

        var result = _manager.WriteFile("subdir/test.bin", content);

        Assert.True(result);
        var fullPath = Path.Combine(_tempDir, "subdir", "test.bin");
        Assert.True(File.Exists(fullPath));
        Assert.Equal(content, File.ReadAllBytes(fullPath));
        // No leftover .tmp file
        Assert.False(File.Exists(fullPath + ".tmp"));
    }

    [Fact]
    public void WriteFile_CreatesIntermediateDirectories()
    {
        Directory.CreateDirectory(_tempDir);

        var result = _manager.WriteFile("a/b/c/file.txt", new byte[] { 42 });

        Assert.True(result);
        Assert.True(File.Exists(Path.Combine(_tempDir, "a", "b", "c", "file.txt")));
    }

    [Fact]
    public void ReadFile_ReturnsContent()
    {
        Directory.CreateDirectory(_tempDir);
        var content = new byte[] { 10, 20, 30 };
        File.WriteAllBytes(Path.Combine(_tempDir, "data.bin"), content);

        var result = _manager.ReadFile("data.bin");

        Assert.NotNull(result);
        Assert.Equal(content, result);
    }

    [Fact]
    public void ReadFile_MissingFile_ReturnsNull()
    {
        Directory.CreateDirectory(_tempDir);

        var result = _manager.ReadFile("nonexistent.bin");

        Assert.Null(result);
    }

    // -------------------------------------------------------------------------
    // DeleteDirectory
    // -------------------------------------------------------------------------

    [Fact]
    public void DeleteDirectory_RemovesDir()
    {
        Directory.CreateDirectory(_tempDir);
        var subDir = Path.Combine(_tempDir, "old-pack");
        Directory.CreateDirectory(subDir);
        File.WriteAllText(Path.Combine(subDir, "file.txt"), "content");

        var result = _manager.DeleteDirectory("old-pack");

        Assert.True(result);
        Assert.False(Directory.Exists(subDir));
    }

    [Fact]
    public void DeleteDirectory_NonExistentDir_ReturnsTrue()
    {
        Directory.CreateDirectory(_tempDir);

        // Deleting a non-existent directory is idempotent — should succeed
        var result = _manager.DeleteDirectory("does-not-exist");

        Assert.True(result);
    }

    // -------------------------------------------------------------------------
    // GetServerDirectory
    // -------------------------------------------------------------------------

    [Fact]
    public void GetServerDirectory_ReturnsPathWhenExists()
    {
        Directory.CreateDirectory(_tempDir);
        var serverDir = Path.Combine(_tempDir, "current", "whois.nic.uk");
        Directory.CreateDirectory(serverDir);

        var result = _manager.GetServerDirectory("whois.nic.uk");

        Assert.Equal(serverDir, result);
    }

    [Fact]
    public void GetServerDirectory_ReturnsNullWhenMissing()
    {
        Directory.CreateDirectory(_tempDir);

        var result = _manager.GetServerDirectory("whois.nic.uk");

        Assert.Null(result);
    }

    [Fact]
    public void GetServerDirectory_ReturnsNullWhenCurrentDirMissing()
    {
        Directory.CreateDirectory(_tempDir);
        // No "current" subdirectory at all

        var result = _manager.GetServerDirectory("whois.verisign-grs.com");

        Assert.Null(result);
    }

    // -------------------------------------------------------------------------
    // IsSymlink
    // -------------------------------------------------------------------------

    [Fact]
    public void IsSymlink_NonSymlinkPath_ReturnsFalse()
    {
        Directory.CreateDirectory(_tempDir);
        var filePath = Path.Combine(_tempDir, "regular.txt");
        File.WriteAllText(filePath, "not a symlink");

        Assert.False(CacheDirectoryManager.IsSymlink(filePath));
    }

    [Fact]
    public void IsSymlink_NonExistentPath_ReturnsFalse()
    {
        Assert.False(CacheDirectoryManager.IsSymlink(Path.Combine(_tempDir, "ghost.txt")));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>Builds an in-memory zip with the given path→content mapping.</summary>
    private static byte[] BuildZip(Dictionary<string, string> entries)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (path, content) in entries)
            {
                var entry = archive.CreateEntry(path);
                using var stream = entry.Open();
                using var writer = new StreamWriter(stream);
                writer.Write(content);
            }
        }

        return ms.ToArray();
    }

    /// <summary>Builds a zip with a single raw entry using the exact name provided.</summary>
    private static byte[] BuildZipRawEntry(string entryName, string content)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry(entryName);
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream);
            writer.Write(content);
        }

        return ms.ToArray();
    }
}
