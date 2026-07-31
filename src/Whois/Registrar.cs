namespace Whois;

/// <summary>
/// Represents a domain name registrar.
/// </summary>
public sealed class Registrar
{
    /// <summary>
    /// The registrar name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// The registrar's IANA number, if available.
    /// </summary>
    public string? IanaId { get; init; }

    /// <summary>
    /// The URL of the registrar's website.
    /// </summary>
    public string? Url { get; init; }

    /// <summary>
    /// The abuse contact email.
    /// </summary>
    public string? AbuseEmail { get; init; }

    /// <summary>
    /// The abuse contact telephone number.
    /// </summary>
    public string? AbuseTelephoneNumber { get; init; }

    /// <summary>
    /// The hostname of the registrar's WHOIS server.
    /// </summary>
    public HostName? WhoisServer { get; init; }
}
