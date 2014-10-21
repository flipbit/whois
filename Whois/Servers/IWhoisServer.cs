namespace Whois.Servers
{
    /// <summary>
    /// Interface to represent a WHOIS server
    /// </summary>
    public interface IWhoisServer
    {
        /// <summary>
        /// Gets or sets the TLD for this server.
        /// </summary>
        /// <value>
        /// The TLD.
        /// </value>
        string TLD { get; }
 
        /// <summary>
        /// Gets the URL of the WHOIS server.
        /// </summary>
        /// <value>
        /// The URL.
        /// </value>
        string Url { get; }
    }
}