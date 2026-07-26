using System.Text;

namespace Whois.Net;

/// <summary>
/// Fakes out TCP responses for testing
/// </summary>
internal class FakeTcpReader : ITcpReader
{
    private readonly string response;

    public FakeTcpReader(string response)
    {
        this.response = response;
    }

    public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(response);
    }
}
