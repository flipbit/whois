namespace Whois;

/// <summary>
/// Wraps the result of a domain or network lookup, including the structured response,
/// protocol used, raw content, and diagnostics.
/// </summary>
public sealed class LookupResult<T>
{
    public LookupResult(T response, LookupProtocol protocol, string rawContent, LookupDiagnostics diagnostics)
    {
        Response = response;
        Protocol = protocol;
        RawContent = rawContent;
        Diagnostics = diagnostics;
    }

    /// <summary>
    /// The structured lookup response (e.g. <see cref="DomainInfo"/>).
    /// </summary>
    public T Response { get; }

    /// <summary>
    /// The protocol used to perform this lookup.
    /// </summary>
    public LookupProtocol Protocol { get; }

    /// <summary>
    /// The raw response content (WHOIS text or RDAP JSON).
    /// </summary>
    public string RawContent { get; }

    /// <summary>
    /// Diagnostic metadata about the lookup.
    /// </summary>
    public LookupDiagnostics Diagnostics { get; }
}
