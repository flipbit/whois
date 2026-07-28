namespace Whois.Servers;

/// <summary>
/// Provides RDAP server discovery by fetching and caching IANA bootstrap data.
/// </summary>
public interface IRdapRegistryCache
{
    /// <summary>
    /// Gets the RDAP base URL for the given TLD, or null if RDAP is not available.
    /// </summary>
    public Task<string?> GetBaseUrl(string tld, CancellationToken ct = default);

    /// <summary>
    /// Clears the cached RDAP bootstrap data. The next lookup will re-fetch from IANA.
    /// </summary>
    public void ClearCache();
}
