namespace Whois.Servers;

/// <summary>
/// Provides WHOIS server discovery by querying whois.iana.org for TLD-to-server mappings.
/// Results are cached per-TLD with a configurable TTL.
/// </summary>
public interface IIanaServerLookup
{
    /// <summary>
    /// Gets the WHOIS server hostname for the given TLD, or null if unknown.
    /// </summary>
    public Task<string?> GetWhoisServer(string tld, CancellationToken ct = default);

    /// <summary>
    /// Gets the WHOIS server for the given IP address by querying IANA.
    /// Results are not cached.
    /// </summary>
    public Task<string?> GetWhoisServer(System.Net.IPAddress address, CancellationToken ct = default);

    /// <summary>
    /// Clears all cached TLD-to-server mappings. Subsequent lookups will re-query IANA.
    /// </summary>
    public void ClearCache();
}
