using System;
using System.Collections.Generic;

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
            NameServers = new List<string>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServer"/> class.
        /// </summary>
        public WhoisServer(string tld, string url) : this()
        {
            Tld = tld;
            Url = url;
        }

        /// <summary>
        /// The status of the WHOIS server lookup
        /// </summary>
        public WhoisResponseStatus Status { get; set; }

        /// <summary>
        /// Gets or sets the TLD for this server.
        /// </summary>
        public string Tld { get; set;  }

        /// <summary>
        /// Gets the URL of the WHOIS server.
        /// </summary>
        public string Url { get; set; }

        /// <summary>
        /// Contains the response content
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Gets or sets the organization.
        /// </summary>
        public Organization Organization { get; set; }

        /// <summary>
        /// Gets or sets the admin contact.
        /// </summary>
        public Contact AdminContact { get; set; }

        /// <summary>
        /// Gets or sets the tech contact.
        /// </summary>
        public Contact TechContact { get; set; }

        /// <summary>
        /// Gets the name servers.
        /// </summary>
        public IList<string> NameServers { get; internal set; }

        /// <summary>
        /// Gets or sets any remarks about this TLD.
        /// </summary>
        public string Remarks { get; set; }

        /// <summary>
        /// Gets or sets the TLD creation date.
        /// </summary>
        public DateTime? Created { get; set; }

        /// <summary>
        /// Gets or sets the date the TLD was last changed.
        /// </summary>
        public DateTime? Changed { get; set; }
    }
}
