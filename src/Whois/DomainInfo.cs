namespace Whois;

/// <summary>
/// Contains structured domain registration data from a WHOIS or RDAP lookup.
/// </summary>
public sealed class DomainInfo
{
    /// <summary>
    /// The queried domain name.
    /// </summary>
    public HostName? DomainName { get; init; }

    /// <summary>
    /// The registry's domain identifier.
    /// </summary>
    public string? RegistryDomainId { get; init; }

    /// <summary>
    /// The registration status of the domain.
    /// </summary>
    public RegistrationStatus Status { get; init; }

    /// <summary>
    /// Detailed domain status strings (e.g. EPP status codes).
    /// </summary>
    public IReadOnlyList<string> DomainStatus { get; init; } = [];

    /// <summary>
    /// The date the domain was registered.
    /// </summary>
    public DateTime? Registered { get; init; }

    /// <summary>
    /// The date the domain was last updated.
    /// </summary>
    public DateTime? Updated { get; init; }

    /// <summary>
    /// The date the domain registration expires.
    /// </summary>
    public DateTime? Expiration { get; init; }

    /// <summary>
    /// The domain's registrar.
    /// </summary>
    public Registrar? Registrar { get; init; }

    /// <summary>
    /// The registrant contact.
    /// </summary>
    public Contact? Registrant { get; init; }

    /// <summary>
    /// The technical contact.
    /// </summary>
    public Contact? TechnicalContact { get; init; }

    /// <summary>
    /// The administrative contact.
    /// </summary>
    public Contact? AdminContact { get; init; }

    /// <summary>
    /// The billing contact.
    /// </summary>
    public Contact? BillingContact { get; init; }

    /// <summary>
    /// The zone contact.
    /// </summary>
    public Contact? ZoneContact { get; init; }

    /// <summary>
    /// The domain's name servers.
    /// </summary>
    public IReadOnlyList<string> NameServers { get; init; } = [];

    /// <summary>
    /// Remarks about the domain registration.
    /// </summary>
    public string? Remarks { get; init; }

    /// <summary>
    /// The DNSSEC status.
    /// </summary>
    public string? DnsSecStatus { get; init; }

    /// <summary>
    /// Trademark information associated with this registration.
    /// </summary>
    public Trademark? Trademark { get; init; }
}
