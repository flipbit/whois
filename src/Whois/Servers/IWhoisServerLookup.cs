namespace Whois.Servers;

/// <summary>
/// Interface to lookup the appropriate root WHOIS server for a given request.
/// </summary>
public interface IWhoisServerLookup
{
    /// <summary>
    /// Lookups the root WHOIS server for the specified request.
    /// </summary>
    public Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default);
}
