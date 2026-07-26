namespace Whois;

/// <summary>
/// Represents a lookup object that reads WHOIS information about domain and IP address registrations
/// </summary>
public interface IWhoisLookup
{
    public Task<LookupResult<DomainInfo>> Lookup(string domain, CancellationToken ct = default);
    public Task<LookupResult<DomainInfo>> Lookup(WhoisRequest request, CancellationToken ct = default);
}
