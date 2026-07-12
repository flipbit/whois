using System.IO.Compression;
using Microsoft.Extensions.Logging;
using Whois.Net;

namespace Whois.Templates;

/// <summary>
/// Manages the local template cache directory: creates it with restrictive permissions,
/// extracts template pack zips with security checks, and provides atomic file writes.
/// </summary>
// MA0182: Will be consumed by TemplatePackProvider (Task 7) — suppress until then.
#pragma warning disable MA0182
internal sealed class CacheDirectoryManager
#pragma warning restore MA0182
{
    private const long MaxUncompressedBytes = 50L * 1024 * 1024; // 50 MB
    private const int MaxEntryCount = 10_000;

    private readonly string _cacheDirectory;
    private readonly ILogger<CacheDirectoryManager> _logger;

    public CacheDirectoryManager(string cacheDirectory, ILogger<CacheDirectoryManager> logger)
    {
        _cacheDirectory = cacheDirectory;
        _logger = logger;
    }

    /// <summary>
    /// Creates the cache directory with restrictive permissions (0700 on Unix).
    /// Returns false if creation fails.
    /// </summary>
#pragma warning disable CA1031 // Catch any IO/security failure and return false rather than throwing
    public bool EnsureDirectory()
    {
        try
        {
            if (Directory.Exists(_cacheDirectory))
                return true;

            Directory.CreateDirectory(_cacheDirectory);
            ApplyRestrictivePermissions(_cacheDirectory);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create cache directory: {Dir}", _cacheDirectory);
            return false;
        }
    }
#pragma warning restore CA1031

    /// <summary>
    /// Extracts a zip archive to <c>{cacheDirectory}/{targetSubDirectory}</c> with security checks:
    /// zip-slip rejection, 50 MB uncompressed cap, 10,000 entry cap.
    /// Cleans up the target directory on any failure.
    /// Returns false if extraction fails or any security check is violated.
    /// </summary>
#pragma warning disable CA1031 // Catch any extraction failure and return false rather than throwing
    public bool ExtractPack(byte[] zipBytes, string targetSubDirectory)
    {
        var targetDir = Path.Combine(_cacheDirectory, targetSubDirectory);

        // Normalise the target path so our containment check is canonical.
        var canonicalTarget = Path.GetFullPath(targetDir);
        // Ensure trailing separator so that prefix-checking works correctly.
        var canonicalTargetWithSep = canonicalTarget.TrimEnd(Path.DirectorySeparatorChar,
                                                              Path.AltDirectorySeparatorChar)
                                   + Path.DirectorySeparatorChar;

        try
        {
            Directory.CreateDirectory(targetDir);

            using var ms = new MemoryStream(zipBytes);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);

            long totalSize = 0;
            var entryCount = 0;

            foreach (var entry in archive.Entries)
            {
                // Skip directory entries (represented as entries with an empty Name)
                if (string.IsNullOrEmpty(entry.Name))
                    continue;

                entryCount++;
                if (entryCount > MaxEntryCount)
                {
                    _logger.LogWarning("Zip entry count cap exceeded ({Max})", MaxEntryCount);
                    DeleteTargetOnFailure(targetDir);
                    return false;
                }

                var entryPath = entry.FullName;

                // Reject entries with an absolute path component
                if (Path.IsPathRooted(entryPath))
                {
                    _logger.LogWarning("Zip entry has absolute path: {Path}", entryPath);
                    DeleteTargetOnFailure(targetDir);
                    return false;
                }

                var destinationPath = Path.GetFullPath(Path.Combine(canonicalTarget, entryPath));

                // Zip-slip check: destination must be inside the canonical target directory
                if (!destinationPath.StartsWith(canonicalTargetWithSep, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(destinationPath, canonicalTarget, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Zip-slip detected for entry: {Path}", entryPath);
                    DeleteTargetOnFailure(targetDir);
                    return false;
                }

                totalSize += entry.Length;
                if (totalSize > MaxUncompressedBytes)
                {
                    _logger.LogWarning("Zip uncompressed size cap exceeded ({Max} bytes)", MaxUncompressedBytes);
                    DeleteTargetOnFailure(targetDir);
                    return false;
                }

                var destDir = Path.GetDirectoryName(destinationPath)!;
                Directory.CreateDirectory(destDir);

                using var entryStream = entry.Open();
                using var destStream = File.Create(destinationPath);
                entryStream.CopyTo(destStream);
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to extract pack to {Dir}", targetDir);
            DeleteTargetOnFailure(targetDir);
            return false;
        }
    }
#pragma warning restore CA1031

    /// <summary>
    /// Removes a subdirectory of the cache directory and all its contents.
    /// Returns true if the directory was removed or did not exist; false on error.
    /// </summary>
#pragma warning disable CA1031 // Catch any IO failure and return false rather than throwing
    public bool DeleteDirectory(string subDirectory)
    {
        var path = Path.Combine(_cacheDirectory, subDirectory);
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete directory: {Dir}", path);
            return false;
        }
    }
#pragma warning restore CA1031

    /// <summary>
    /// Atomically writes <paramref name="content"/> to <c>{cacheDirectory}/{relativePath}</c>
    /// via a temporary file and rename. Creates intermediate directories as needed.
    /// Returns false on any failure.
    /// </summary>
#pragma warning disable CA1031 // Catch any IO failure and return false rather than throwing
    public bool WriteFile(string relativePath, byte[] content)
    {
        var fullPath = Path.Combine(_cacheDirectory, relativePath);
        var tmpPath = fullPath + ".tmp";

        if (IsSymlink(fullPath))
        {
            _logger.LogWarning("Refusing to write to symlink: {Path}", fullPath);
            return false;
        }

        try
        {
            var dir = Path.GetDirectoryName(fullPath)!;
            Directory.CreateDirectory(dir);

            File.WriteAllBytes(tmpPath, content);
            File.Move(tmpPath, fullPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write file: {Path}", fullPath);
            TryDelete(tmpPath);
            return false;
        }
    }
#pragma warning restore CA1031

    /// <summary>
    /// Reads all bytes from <c>{cacheDirectory}/{relativePath}</c>.
    /// Returns null if the file does not exist or cannot be read.
    /// </summary>
#pragma warning disable CA1031 // Catch any IO failure and return null rather than throwing
    public byte[]? ReadFile(string relativePath)
    {
        var fullPath = Path.Combine(_cacheDirectory, relativePath);
        try
        {
            return File.Exists(fullPath) ? File.ReadAllBytes(fullPath) : null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read file: {Path}", fullPath);
            return null;
        }
    }
#pragma warning restore CA1031

    /// <summary>
    /// Returns true if <paramref name="path"/> is a symbolic link (file or directory).
    /// </summary>
    public static bool IsSymlink(string path)
    {
        try
        {
            var fileInfo = new FileInfo(path);
            if (fileInfo.Exists)
                return NetStandardShims.GetLinkTarget(fileInfo) != null;

            var dirInfo = new DirectoryInfo(path);
            if (dirInfo.Exists)
                return NetStandardShims.GetLinkTarget(dirInfo) != null;

            return false;
        }
#pragma warning disable CA1031 // Swallow any filesystem error — treat as "not a symlink"
        catch
#pragma warning restore CA1031
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the full path to <c>{cacheDirectory}/current/{server}</c> if that directory exists,
    /// or null if it does not.
    /// </summary>
    public string? GetServerDirectory(string server)
    {
        var path = Path.Combine(_cacheDirectory, "current", server);
        return Directory.Exists(path) ? path : null;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static void ApplyRestrictivePermissions(string directory)
    {
        try
        {
            // chmod 700: owner rwx, group ---, other ---; no-op on Windows (ACLs are complex)
            NetStandardShims.SetOwnerOnlyPermissions(directory);
        }
#pragma warning disable CA1031 // Best-effort; do not fail directory creation over a permissions error
        catch
#pragma warning restore CA1031
        {
        }
    }

    private void DeleteTargetOnFailure(string targetDir)
    {
        try
        {
            if (Directory.Exists(targetDir))
                Directory.Delete(targetDir, recursive: true);
        }
#pragma warning disable CA1031 // Best-effort cleanup; log and continue
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger.LogWarning(ex, "Failed to clean up target directory after failure: {Dir}", targetDir);
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
#pragma warning disable CA1031 // Best-effort temp file cleanup
        catch { }
#pragma warning restore CA1031
    }
}
