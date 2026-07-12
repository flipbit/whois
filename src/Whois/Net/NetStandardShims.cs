using System.Net.Sockets;

namespace Whois.Net;

internal static class NetStandardShims
{
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
