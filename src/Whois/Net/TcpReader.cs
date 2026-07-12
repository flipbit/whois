using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace Whois.Net;

/// <summary>
/// Class to allow access to TCP services
/// </summary>
public class TcpReader : ITcpReader
{
    public async Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, CancellationToken cancellationToken = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        var token = timeoutCts.Token;

        using var tcpClient = new TcpClient();
        try
        {
            await NetStandardShims.ConnectAsync(tcpClient, url, port, token).ConfigureAwait(false);

            using var stream = tcpClient.GetStream();
            // Use a BOM-less encoding for the writer to avoid sending a byte order mark
            // to the WHOIS server (which would corrupt the query).
            var writerEncoding = encoding is UTF8Encoding
                ? new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
                : encoding;
            using var writer = new StreamWriter(stream, writerEncoding) { NewLine = "\r\n" };
            using var reader = new StreamReader(stream, encoding);

            await writer.WriteLineAsync(command).ConfigureAwait(false);
            await NetStandardShims.FlushAsync(writer, token).ConfigureAwait(false);

            var sb = new StringBuilder();
            string? line;
            while ((line = await NetStandardShims.ReadLineAsync(reader, token).ConfigureAwait(false)) != null)
            {
                sb.AppendLine(line);
            }
            return sb.ToString();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw new WhoisException(string.Format(CultureInfo.InvariantCulture, "Connection to {0}:{1} timed out after {2} seconds.", url, port, timeoutSeconds));
        }
        catch (SocketException ex)
        {
            throw new WhoisException(string.Format(CultureInfo.InvariantCulture, "Couldn't connect to {0}:{1}: {2}", url, port, ex.Message), ex);
        }
    }
}
