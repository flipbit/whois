using System;
using System.Collections.Generic;

namespace Whois.Servers
{
    /// <summary>
    /// Represents a WHOIS server for a TLD
    /// </summary>
    public class WhoisServerRecord : IWhoisServer
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerRecord"/> class.
        /// </summary>
        public WhoisServerRecord()
        {
            NameServers = new List<string>();
        }

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
        /// Gets or sets the organization.
        /// </summary>
        /// <value>
        /// The organization.
        /// </value>
        public Organization Organization { get; set; }

        /// <summary>
        /// Gets or sets the admin contact.
        /// </summary>
        /// <value>
        /// The admin contact.
        /// </value>
        public Contact AdminContact { get; set; }

        /// <summary>
        /// Gets or sets the tech contact.
        /// </summary>
        /// <value>
        /// The tech contact.
        /// </value>
        public Contact TechContact { get; set; }

        /// <summary>
        /// Gets the name servers.
        /// </summary>
        /// <value>
        /// The name servers.
        /// </value>
        public IList<string> NameServers { get; private set; }

        /// <summary>
        /// Gets or sets any remarks about this TLD.
        /// </summary>
        /// <value>
        /// The remarks.
        /// </value>
        public string Remarks { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>
        /// The created.
        /// </value>
        public DateTime Created { get; set; }

        /// <summary>
        /// Gets or sets the change date.
        /// </summary>
        /// <value>
        /// The modified.
        /// </value>
        public DateTime Changed { get; set; }

        /// <summary>
        /// Gets or sets the raw response.
        /// </summary>
        /// <value>
        /// The raw response.
        /// </value>
        public string RawResponse { get; set; }
    }
}
