namespace Whois.Models
{
    /// <summary>
    /// Represents WHOIS information for a domain.
    /// </summary>
    public class WhoisResponse 
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisResponse"/> class.
        /// </summary>
        public WhoisResponse()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisResponse"/> class.
        /// </summary>
        public WhoisResponse(string content)
        {
            Content = content;
        }

        /// <summary>
        /// Gets or sets the WHOIS response
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Gets or sets the domain.
        /// </summary>
        /// <value>The domain.</value>
        public string Domain { get; set; }

        /// <summary>
        /// Holds the parsed WHOIS response
        /// </summary>
        public ParsedWhoisResponse ParsedResponse { get; set; }
    }
}