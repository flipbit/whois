namespace Whois;

/// <summary>
/// Represents a contact associated with a domain registration.
/// </summary>
public class Contact
{
    /// <summary>
    /// The registry's identifier for this contact.
    /// </summary>
    public string? RegistryId { get; init; }

    /// <summary>
    /// The contact name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// The organization name.
    /// </summary>
    public string? Organization { get; init; }

    /// <summary>
    /// The postal address.
    /// </summary>
    public Address? Address { get; init; }

    /// <summary>
    /// The telephone number.
    /// </summary>
    public string? TelephoneNumber { get; init; }

    /// <summary>
    /// The telephone number extension.
    /// </summary>
    public string? TelephoneNumberExt { get; init; }

    /// <summary>
    /// The fax number.
    /// </summary>
    public string? FaxNumber { get; init; }

    /// <summary>
    /// The fax number extension.
    /// </summary>
    public string? FaxNumberExt { get; init; }

    /// <summary>
    /// The email address.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// The date the contact was created, if available.
    /// </summary>
    public DateTime? Created { get; init; }

    /// <summary>
    /// The date the contact was last updated, if available.
    /// </summary>
    public DateTime? Updated { get; init; }
}
