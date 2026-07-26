using System.Net.Sockets;
#if NETSTANDARD2_0
using System.Runtime.InteropServices;
#endif

namespace Whois.Net;

internal static class NetStandardShims
{
    /// <summary>
    /// Returns true when running on Windows. Shims <c>OperatingSystem.IsWindows()</c> for netstandard2.0.
    /// </summary>
    public static bool IsWindows()
    {
#if NETSTANDARD2_0
        return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
#else
        return OperatingSystem.IsWindows();
#endif
    }

    /// <summary>
    /// Sets Unix file permissions (0700) on <paramref name="path"/> when running on a Unix platform.
    /// No-op on Windows or netstandard2.0 (where the API is unavailable).
    /// </summary>
    public static void SetOwnerOnlyPermissions(string path)
    {
#if NETSTANDARD2_0
        // SetUnixFileMode is not available on netstandard2.0; skip silently.
#else
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
#endif
    }

    /// <summary>
    /// Returns the symlink target of a filesystem entry, or null if it is not a symlink.
    /// Shims <c>FileSystemInfo.LinkTarget</c> for netstandard2.0.
    /// </summary>
    public static string? GetLinkTarget(FileSystemInfo info)
    {
#if NETSTANDARD2_0
        // LinkTarget is not available on netstandard2.0; no symlink detection possible.
        return null;
#else
        return info.LinkTarget;
#endif
    }


    public static Task ConnectAsync(TcpClient client, string host, int port, CancellationToken cancellationToken)
    {
#if NETSTANDARD2_0
        cancellationToken.ThrowIfCancellationRequested();
        return client.ConnectAsync(host, port);
#else
        return client.ConnectAsync(host, port, cancellationToken).AsTask();
#endif
    }

    public static Task<string?> ReadLineAsync(StreamReader reader, CancellationToken cancellationToken)
    {
#if NETSTANDARD2_0
        cancellationToken.ThrowIfCancellationRequested();
        return reader.ReadLineAsync();
#else
        return reader.ReadLineAsync(cancellationToken).AsTask();
#endif
    }

    public static Task FlushAsync(StreamWriter writer, CancellationToken cancellationToken)
    {
#if NETSTANDARD2_0
        cancellationToken.ThrowIfCancellationRequested();
        return writer.FlushAsync();
#else
        return writer.FlushAsync(cancellationToken);
#endif
    }
}
