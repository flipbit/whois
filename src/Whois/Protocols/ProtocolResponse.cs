namespace Whois.Protocols;

/// <summary>
/// Internal result from a protocol client, containing the parsed response and diagnostics.
/// </summary>
internal sealed class ProtocolResponse
{
    public required string RawContent { get; init; }
    public required LookupProtocol Protocol { get; init; }
    public required DomainInfo Response { get; init; }
    public required LookupDiagnostics Diagnostics { get; init; }
}
