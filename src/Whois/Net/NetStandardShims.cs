using System.Net.Sockets;
#if NETSTANDARD2_0
using System.Runtime.InteropServices;
#endif

namespace Whois.Net;

internal static class NetStandardShims
{
    /// <summary>
    /// Creates an <see cref="HttpClient"/> with connection pooling where the runtime supports it.
    /// On net8.0+, uses <c>SocketsHttpHandler</c> with a 2-minute pooled connection lifetime.
    /// On netstandard2.0, falls back to a plain <c>HttpClientHandler</c>.
    /// </summary>
#pragma warning disable CA2000 // Handler ownership transfers to HttpClient
    public static HttpClient CreatePooledHttpClient()
    {
#if NETSTANDARD2_0
        return new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
#else
        return new HttpClient(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AllowAutoRedirect = false,
        });
#endif
    }
#pragma warning restore CA2000

    /// <summary>
    /// Creates an <see cref="HttpMessageHandler"/> suitable for use as a named <c>HttpClient</c> primary
    /// handler when registered via DI. Auto-redirect is disabled so the caller can validate redirect
    /// targets before following them. On net8.0+, uses <c>SocketsHttpHandler</c> with connection pooling.
    /// On netstandard2.0, falls back to a plain <c>HttpClientHandler</c>.
    /// </summary>
#pragma warning disable CA2000 // Handler ownership transfers to HttpClientFactory
    public static HttpMessageHandler CreateNonRedirectingHandler()
    {
#if NETSTANDARD2_0
        return new HttpClientHandler { AllowAutoRedirect = false };
#else
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };
#endif
    }
#pragma warning restore CA2000

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

    public static Task<Stream> ReadAsStreamAsync(System.Net.Http.HttpContent content, CancellationToken ct)
    {
#if NETSTANDARD2_0
        // netstandard2.0 doesn't support CancellationToken on ReadAsStreamAsync; ignore it.
        return content.ReadAsStreamAsync();
#else
        return content.ReadAsStreamAsync(ct);
#endif
    }
}
