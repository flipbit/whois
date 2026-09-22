namespace Whois;

/// <summary>
/// Represents a request to look up domain registration data.
/// </summary>
public class DomainRequest : LookupRequest
{
    /// <summary>
    /// Creates a new domain lookup request.
    /// </summary>
    /// <param name="query">The domain name to look up.</param>
    public DomainRequest(string query)
    {
        Query = query;
    }

    /// <summary>
    /// The domain name to look up.
    /// </summary>
    public string Query { get; }
}
