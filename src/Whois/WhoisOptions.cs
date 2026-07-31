using System.Text;

namespace Whois;

/// <summary>
/// Specifies options for looking up WHOIS information
/// </summary>
public class WhoisOptions
{
    /// <summary>
    /// The default encoding to use.
    /// </summary>
    public Encoding Encoding { get; set; } = Encoding.UTF8;

    /// <summary>
    /// Defines the network timeout to use when communicating with servers.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// Determines whether to follow referral links when downloading WHOIS data.
    /// </summary>
    public bool FollowReferrer { get; set; } = true;

    /// <summary>
    /// The preferred lookup protocol. Defaults to Auto (RDAP when available, falls back to WHOIS).
    /// </summary>
    public ProtocolPreference PreferredProtocol { get; set; } = ProtocolPreference.Auto;

    /// <summary>
    /// URL to fetch RDAP bootstrap data from. Defaults to the IANA registry.
    /// Override for testing or air-gapped deployments using a local mirror.
    /// </summary>
    public string RdapBootstrapUrl { get; set; } = "https://data.iana.org/rdap/dns.json";

    /// <summary>
    /// Maximum number of HTTP redirects to follow for RDAP requests.
    /// </summary>
    public int MaxRdapRedirects { get; set; } = 5;

    /// <summary>
    /// Maximum number of WHOIS referral hops to follow (e.g. Verisign to registrar).
    /// </summary>
    public int MaxWhoisReferralDepth { get; set; } = 10;

    /// <summary>
    /// Maximum size in characters for an RDAP response body. Responses exceeding this limit are rejected.
    /// </summary>
    public int MaxRdapResponseSize { get; set; } = 2 * 1024 * 1024;

    /// <summary>
    /// Maximum size in characters for the RDAP bootstrap JSON download.
    /// </summary>
    public int MaxRdapBootstrapResponseSize { get; set; } = 1 * 1024 * 1024;

    /// <summary>
    /// How long to cache TLD-to-server mappings before re-fetching. Used by both RDAP and WHOIS caches.
    /// </summary>
    public TimeSpan TldServerCacheDuration { get; set; } = TimeSpan.FromHours(24);

}
