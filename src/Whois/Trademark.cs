namespace Whois;

/// <summary>
/// Represents trademark information embedded in a domain registration.
/// </summary>
public class Trademark
{
    /// <summary>
    /// The trademark name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// The date of the trademark.
    /// </summary>
    public DateTime? Date { get; init; }

    /// <summary>
    /// The country where the trademark is registered.
    /// </summary>
    public string? Country { get; init; }

    /// <summary>
    /// The trademark number.
    /// </summary>
    public int? Number { get; init; }
}
