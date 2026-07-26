namespace Whois.Protocols;

/// <summary>
/// Abstraction for a protocol-specific lookup client (WHOIS or RDAP).
/// </summary>
internal interface IProtocolClient
{
    /// <summary>
    /// The protocol this client implements.
    /// </summary>
    public LookupProtocol Protocol { get; }

    /// <summary>
    /// Queries for the given domain using this protocol.
    /// </summary>
    public Task<ProtocolResponse> Query(WhoisRequest request, CancellationToken ct);
}
