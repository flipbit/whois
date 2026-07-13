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
