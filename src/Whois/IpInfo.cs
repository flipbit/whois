namespace Whois;

/// <summary>
/// Contains structured IP network registration data from a WHOIS or RDAP lookup.
/// </summary>
public sealed class IpInfo : IRegistrationInfo
{
    /// <summary>
    /// The network range (e.g. "8.8.8.0 - 8.8.8.255").
    /// </summary>
    public string? Network { get; init; }

    /// <summary>
    /// The CIDR notation (e.g. "8.8.8.0/24").
    /// </summary>
    public string? Cidr { get; init; }

    /// <summary>
    /// The network name assigned by the registry.
    /// </summary>
    public string? NetName { get; init; }

    /// <summary>
    /// The organization that holds this allocation.
    /// </summary>
    public string? Organization { get; init; }

    /// <summary>
    /// The country code for this allocation.
    /// </summary>
    public string? Country { get; init; }

    /// <summary>
    /// The Regional Internet Registry or source of this data (e.g. "ARIN", "RIPE NCC").
    /// </summary>
    public string? Rir { get; init; }

    /// <summary>
    /// The registration status.
    /// </summary>
    public RegistrationStatus Status { get; init; }

    /// <summary>
    /// The date this allocation was registered.
    /// </summary>
    public DateTime? Registered { get; init; }

    /// <summary>
    /// The date this allocation was last updated.
    /// </summary>
    public DateTime? Updated { get; init; }

    /// <summary>
    /// Remarks about this allocation.
    /// </summary>
    public string? Remarks { get; init; }

    /// <summary>
    /// The abuse contact for this network.
    /// </summary>
    public Contact? AbuseContact { get; init; }

    /// <summary>
    /// The administrative contact.
    /// </summary>
    public Contact? AdminContact { get; init; }

    /// <summary>
    /// The technical contact.
    /// </summary>
    public Contact? TechnicalContact { get; init; }
}
