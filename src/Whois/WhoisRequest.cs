using System.Text;

namespace Whois;

/// <summary>
/// Represents a request to query WHOIS information
/// </summary>
public class WhoisRequest
{
    public WhoisRequest(string query)
    {
        Query = query;
    }

    /// <summary>
    /// The WHOIS query, typically the domain name
    /// </summary>
    public string Query { get; }

    /// <summary>
    /// The encoding to use whilst reading data from the WHOIS server
    /// </summary>
    public Encoding? Encoding { get; init; }

    /// <summary>
    /// The network timeout to use whilst reading data from the WHOIS server
    /// </summary>
    public int? TimeoutSeconds { get; init; }

    /// <summary>
    /// If true, referral links within WHOIS responses will be followed.
    /// </summary>
    public bool? FollowReferrer { get; init; }

    /// <summary>
    /// The preferred lookup protocol.
    /// </summary>
    public ProtocolPreference? PreferredProtocol { get; init; }

    /// <summary>
    /// If set, the given WHOIS server will be queried. If null, the WHOIS
    /// server for the domain TLD will be attempted to be found automatically.
    /// </summary>
    public HostName? WhoisServer { get; init; }
}
