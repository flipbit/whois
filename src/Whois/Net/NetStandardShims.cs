using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Whois.Net
{
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
    }
}
