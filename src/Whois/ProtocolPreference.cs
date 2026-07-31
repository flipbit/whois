namespace Whois;

/// <summary>
/// Specifies which lookup protocol to use for a query.
/// </summary>
public enum ProtocolPreference
{
    /// <summary>
    /// Automatically select the best protocol based on IANA bootstrap data.
    /// Uses RDAP when available, falls back to WHOIS.
    /// </summary>
    Auto,

    /// <summary>
    /// Force legacy WHOIS protocol (TCP port 43).
    /// </summary>
    Whois,

    /// <summary>
    /// Force RDAP protocol (HTTPS/JSON). Throws if RDAP is not available for the TLD.
    /// </summary>
    Rdap,
}
