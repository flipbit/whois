namespace Whois.Servers
{
    /// <summary>
    /// Represents a WHOIS server for a domain
    /// </summary>
    public class WhoisServer : IWhoisServer
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServer"/> class.
        /// </summary>
        /// <param name="tld">The TLD.</param>
        /// <param name="url">The URL.</param>
        public WhoisServer(string tld, string url)
        {
            TLD = tld;
            Url = url;
        }

        /// <summary>
        /// Gets or sets the TLD for this server.
        /// </summary>
        /// <value>
        /// The TLD.
        /// </value>
        public string TLD { get; private set; }

        /// <summary>
        /// Gets the URL of the WHOIS server.
        /// </summary>
        /// <value>
        /// The URL.
        /// </value>
        public string Url { get; private set; }
    }
}
