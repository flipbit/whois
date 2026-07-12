using System.Text;

namespace Whois;

/// <summary>
/// Represents a Lookup object that reads WHOIS information about domain and IP address registrations
/// </summary>
public interface IWhoisLookup
{
    /// <summary>
    /// Performs a WHOIS lookup on the specified domain.
    /// </summary>
    public Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a WHOIS lookup on the specified domain with the given encoding.
    /// </summary>
    public Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs a WHOIS lookup for the given request.
    /// </summary>
    public Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default);
}
