namespace WhoisRefresh.Infrastructure;

public interface IFileSystem
{
    Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default);
    Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default);
    bool FileExists(string path);
    bool DirectoryExists(string path);
    void CreateDirectory(string path);

    /// <summary>
    /// Returns the content of <paramref name="repoRelativePath"/> as it exists in the HEAD
    /// commit via <c>git show HEAD:&lt;path&gt;</c>. Returns <c>null</c> if the file is not
    /// tracked (new file, or git command fails).
    /// </summary>
    Task<string?> GitReadHeadAsync(string repoRoot, string repoRelativePath, CancellationToken cancellationToken = default);
}
