namespace Whois
{
    /// <summary>
    /// Represents a Lookup object that reads WHOIS information about domain and IP address registrations
    /// </summary>
    public interface IWhoisLookup
    {
        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        WhoisRecord Lookup(string domain);
    }
}
