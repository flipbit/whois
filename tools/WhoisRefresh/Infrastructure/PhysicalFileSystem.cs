namespace WhoisRefresh.Infrastructure;

public class PhysicalFileSystem : IFileSystem
{
    public Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default)
        => File.ReadAllTextAsync(path, cancellationToken);

    public Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default)
        => File.WriteAllTextAsync(path, content, cancellationToken);

    public bool FileExists(string path) => File.Exists(path);

    public bool DirectoryExists(string path) => Directory.Exists(path);

    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
}
