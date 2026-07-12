namespace WhoisRefresh.Infrastructure;

public interface IFileSystem
{
    Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default);
    Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default);
    bool FileExists(string path);
    bool DirectoryExists(string path);
    void CreateDirectory(string path);
}
