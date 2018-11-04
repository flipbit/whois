namespace Whois.Models
{
    /// <summary>
    /// Represents a WHOIS server for a domain
    /// </summary>
    public class WhoisServer
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServer"/> class.
        /// </summary>
        public WhoisServer()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServer"/> class.
        /// </summary>
        public WhoisServer(string tld, string url)
        {
            Tld = tld;
            Url = url;
        }

        /// <summary>
        /// Gets or sets the TLD for this server.
        /// </summary>
        /// <value>
        /// The TLD.
        /// </value>
        public string Tld { get; set;  }

        /// <summary>
        /// Gets the URL of the WHOIS server.
        /// </summary>
        /// <value>
        /// The URL.
        /// </value>
        public string Url { get; set; }

        /// <summary>
        /// Contains the response content
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Contains parsed WHOIS server details
        /// </summary>
        public ParsedWhoisServer ParsedWhoisServer { get; set; }
    }
}
