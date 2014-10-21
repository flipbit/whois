namespace Whois.Servers
{
    /// <summary>
    /// Represents a WHOIS server for a TLD
    /// </summary>
    public class WhoisServerRecord : IWhoisServer
    {
        /// <summary>
        /// Gets or sets the TLD.
        /// </summary>
        /// <value>
        /// The TLD.
        /// </value>
        public string TLD { get; set; }

        /// <summary>
        /// Gets or sets the URL of the WHOIS server for this TLD.
        /// </summary>
        /// <value>
        /// The URL.
        /// </value>
        public string Url { get; set; }

        /// <summary>
        /// Gets or sets any remarks about this TLD.
        /// </summary>
        /// <value>
        /// The remarks.
        /// </value>
        public string Remarks { get; set; }

        /// <summary>
        /// Gets or sets the raw response.
        /// </summary>
        /// <value>
        /// The raw response.
        /// </value>
        public string RawResponse { get; set; }
    }
}
