namespace Whois.Servers;

/// <summary>
/// Provides server discovery for both RDAP and WHOIS protocols using IANA bootstrap data.
/// </summary>
public interface IBootstrapRegistry
{
    /// <summary>
    /// Gets the RDAP base URL for the given TLD, or null if RDAP is not available.
    /// </summary>
    public Task<string?> GetRdapBaseUrl(string tld, CancellationToken ct);

    /// <summary>
    /// Gets the WHOIS server hostname for the given TLD, or null if unknown.
    /// </summary>
    public Task<string?> GetWhoisServer(string tld, CancellationToken ct);

    /// <summary>
    /// Forces an immediate refresh of the bootstrap data from IANA.
    /// </summary>
    public Task Refresh(CancellationToken ct);
}
