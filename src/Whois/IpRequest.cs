using System.Net;

namespace Whois;

/// <summary>
/// Represents a request to look up IP address registration data.
/// </summary>
public class IpRequest : LookupRequest
{
    /// <summary>
    /// Creates a new IP lookup request from an <see cref="IPAddress"/>.
    /// </summary>
    /// <param name="address">The IP address to look up.</param>
    public IpRequest(IPAddress address)
    {
        Address = address;
    }

    /// <summary>
    /// Creates a new IP lookup request by parsing the given string.
    /// </summary>
    /// <param name="address">An IPv4 or IPv6 address string.</param>
    /// <exception cref="FormatException">Thrown when the string is not a valid IP address.</exception>
    public IpRequest(string address)
    {
        Address = IPAddress.Parse(address);
    }

    /// <summary>
    /// The IP address to look up.
    /// </summary>
    public IPAddress Address { get; }
}
