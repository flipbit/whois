namespace Whois;

/// <summary>
/// Represents a postal address with both unstructured lines and optional structured fields.
/// <see cref="Lines"/> is always populated regardless of data source.
/// Structured fields are populated when available (e.g. from RDAP) and null otherwise.
/// </summary>
public sealed class Address
{
    /// <summary>
    /// Address formatted as display lines. Always populated for both WHOIS and RDAP sources.
    /// </summary>
    public IReadOnlyList<string> Lines { get; init; } = [];

    /// <summary>
    /// Street address lines. Populated from RDAP (multi-line per RFC 9083 vCard adr), null from WHOIS.
    /// </summary>
    public IReadOnlyList<string>? Street { get; init; }

    /// <summary>
    /// City or locality. Populated from RDAP, null from WHOIS.
    /// </summary>
    public string? City { get; init; }

    /// <summary>
    /// State, province, or region. Populated from RDAP, null from WHOIS.
    /// </summary>
    public string? Region { get; init; }

    /// <summary>
    /// Postal or ZIP code. Populated from RDAP, null from WHOIS.
    /// </summary>
    public string? PostalCode { get; init; }

    /// <summary>
    /// Country name or code. Populated from RDAP, null from WHOIS.
    /// </summary>
    public string? Country { get; init; }
}
