namespace Whois;

/// <summary>
/// Common properties shared by all registration info types (domain, IP, ASN).
/// </summary>
public interface IRegistrationInfo
{
    /// <summary>
    /// The registration status.
    /// </summary>
    public RegistrationStatus Status { get; }

    /// <summary>
    /// The date the registration was created.
    /// </summary>
    public DateTime? Registered { get; }

    /// <summary>
    /// The date the registration was last updated.
    /// </summary>
    public DateTime? Updated { get; }

    /// <summary>
    /// Remarks about the registration.
    /// </summary>
    public string? Remarks { get; }
}
