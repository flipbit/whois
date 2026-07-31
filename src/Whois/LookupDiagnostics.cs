namespace Whois;

/// <summary>
/// Contains diagnostic metadata about how a lookup was performed.
/// </summary>
public sealed class LookupDiagnostics
{
    /// <summary>
    /// The number of fields successfully parsed from the response.
    /// </summary>
    public int FieldsParsed { get; init; }

    /// <summary>
    /// The number of parsing errors encountered.
    /// </summary>
    public int ParsingErrors { get; init; }

    /// <summary>
    /// The template used to parse a WHOIS response. Null for RDAP.
    /// </summary>
    public string? TemplateName { get; init; }

    /// <summary>
    /// The chain of WHOIS servers followed during referral resolution.
    /// </summary>
    public IReadOnlyList<string> ReferralChain { get; init; } = [];

    /// <summary>
    /// The total time taken for the lookup.
    /// </summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// The RDAP endpoint URL or WHOIS server hostname that served the response.
    /// </summary>
    public string? ServerUrl { get; init; }

    /// <summary>
    /// The HTTP status code from an RDAP response. Null for WHOIS.
    /// </summary>
    public int? HttpStatusCode { get; init; }
}
