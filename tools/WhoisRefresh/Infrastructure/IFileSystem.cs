namespace WhoisRefresh.Infrastructure;

public interface IFileSystem
{
    public Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default);
    public Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default);
    public bool FileExists(string path);
    public bool DirectoryExists(string path);
    public void CreateDirectory(string path);

    /// <summary>
    /// Returns the content of <paramref name="repoRelativePath"/> as it exists in the HEAD
    /// commit via <c>git show HEAD:&lt;path&gt;</c>. Returns <see langword="null"/> if the file is not
    /// tracked (new file, or git command fails).
    /// </summary>
    public Task<string?> GitReadHeadAsync(string repoRoot, string repoRelativePath, CancellationToken cancellationToken = default);
}
