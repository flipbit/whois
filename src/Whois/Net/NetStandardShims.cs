using System.Net.Sockets;
using System.Text;

namespace Whois.Net;

internal static class NetStandardShims
{
    private static readonly TimeSpan PooledConnectionLifetime = TimeSpan.FromMinutes(2);
    private const int StreamingBufferSize = 8192;
    private const int DefaultStringBuilderCapacity = 1024;

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
            PooledConnectionLifetime = PooledConnectionLifetime,
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
            PooledConnectionLifetime = PooledConnectionLifetime,
        };
#endif
    }
#pragma warning restore CA2000

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

    /// <summary>
    /// Reads an HTTP response body into a string, enforcing a maximum character limit.
    /// Streams the response to avoid loading the full content-length into memory up front.
    /// </summary>
    internal static async Task<string> ReadWithSizeLimit(
        HttpResponseMessage response, int maxChars, CancellationToken ct)
    {
        using var stream = await ReadAsStreamAsync(response.Content, ct).ConfigureAwait(false);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var buffer = new char[StreamingBufferSize];
        var capacity = (int)Math.Min(
            response.Content.Headers.ContentLength ?? DefaultStringBuilderCapacity, maxChars);
        var sb = new StringBuilder(capacity);
        int charsRead;

        while ((charsRead = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            sb.Append(buffer, 0, charsRead);
            if (sb.Length > maxChars)
            {
                throw new WhoisException(
                    FormattableString.Invariant(
                        $"Response exceeds maximum size of {maxChars} characters"));
            }
        }

        return sb.ToString();
    }
}
