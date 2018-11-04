using System;
using System.Collections.Generic;

namespace Whois.Models
{
    /// <summary>
    /// Represents a WHOIS server for a TLD
    /// </summary>
    public class ParsedWhoisServer 
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ParsedWhoisServer"/> class.
        /// </summary>
        public ParsedWhoisServer()
        {
            NameServers = new List<string>();
        }

        public string Tld { get; set; }

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
        public IList<string> NameServers { get; }

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
    }
}
