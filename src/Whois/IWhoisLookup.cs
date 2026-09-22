using System.Net;

namespace Whois;

/// <summary>
/// Represents a lookup object that reads WHOIS information about domain and IP address registrations.
/// </summary>
public interface IWhoisLookup
{
    /// <summary>
    /// Looks up domain registration data by domain name string.
    /// </summary>
    public Task<LookupResult<DomainInfo>> Lookup(string domain, CancellationToken ct = default);

    /// <summary>
    /// Looks up domain registration data using a structured request.
    /// </summary>
    public Task<LookupResult<DomainInfo>> Lookup(DomainRequest request, CancellationToken ct = default);

    /// <summary>
    /// Looks up IP address registration data.
    /// </summary>
    public Task<LookupResult<IpInfo>> Lookup(IPAddress address, CancellationToken ct = default);

    /// <summary>
    /// Looks up IP address registration data using a structured request.
    /// </summary>
    public Task<LookupResult<IpInfo>> Lookup(IpRequest request, CancellationToken ct = default);

    /// <summary>
    /// Auto-detects the query type (domain or IP) and performs the appropriate lookup.
    /// </summary>
    public Task<LookupResult<IRegistrationInfo>> Query(string query, CancellationToken ct = default);

    /// <summary>
    /// Clears all cached server discovery data (both RDAP and WHOIS).
    /// </summary>
    public void ClearCache();
}
