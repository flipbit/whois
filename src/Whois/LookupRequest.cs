using System.Text;

namespace Whois;

/// <summary>
/// Base class for all lookup requests, containing shared options.
/// </summary>
public abstract class LookupRequest
{
    /// <summary>
    /// The encoding to use when reading data from WHOIS servers.
    /// </summary>
    public Encoding? Encoding { get; init; }

    /// <summary>
    /// The network timeout in seconds.
    /// </summary>
    public int? TimeoutSeconds { get; init; }

    /// <summary>
    /// If true, referral links within responses will be followed.
    /// </summary>
    public bool? FollowReferrer { get; init; }

    /// <summary>
    /// The preferred lookup protocol.
    /// </summary>
    public ProtocolPreference? PreferredProtocol { get; init; }

    /// <summary>
    /// If set, overrides automatic server discovery.
    /// </summary>
    public HostName? WhoisServer { get; init; }

    /// <summary>
    /// If set, overrides the default port (43) for WHOIS TCP connections.
    /// </summary>
    public int? Port { get; init; }

    /// <summary>
    /// Pre-resolved RDAP base URL. Set internally by the orchestrator to
    /// avoid a redundant registry lookup in the protocol client.
    /// </summary>
    internal string? RdapBaseUrl { get; set; }
}
