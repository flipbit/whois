using System.Diagnostics;

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

    public async Task<string?> GitReadHeadAsync(string repoRoot, string repoRelativePath, CancellationToken cancellationToken = default)
    {
        try
        {
            // git show HEAD:<path> — uses forward slashes as required by git
            var gitPath = repoRelativePath.Replace('\\', '/');
            var psi = new ProcessStartInfo("git", $"show HEAD:{gitPath}")
            {
                WorkingDirectory = repoRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            if (process == null) return null;

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            return process.ExitCode == 0 ? output : null;
        }
        catch
        {
            return null;
        }
    }
}
