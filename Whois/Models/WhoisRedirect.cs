using System;
using System.Collections.Generic;

namespace Whois.Models
{
    /// <summary>
    /// Represents a redirect returned from a WHOIS server.  A redirect will specify a further
    /// WHOIS server to query, typically a specific registar's WHOIS server.
    /// </summary>
    public class WhoisRedirect
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisRedirect"/> class.
        /// </summary>
        public WhoisRedirect()
        {
            Nameservers = new List<string>();
        }

        /// <summary>
        /// Gets or sets the domain.
        /// </summary>
        /// <value>
        /// The domain.
        /// </value>
        public string Domain { get; set; }

        /// <summary>
        /// Gets or sets the registrar.
        /// </summary>
        /// <value>
        /// The registrar.
        /// </value>
        public string Registrar { get; set; }

        /// <summary>
        /// Gets or sets the URL.
        /// </summary>
        /// <value>
        /// The URL.
        /// </value>
        public string Url { get; set; }

        /// <summary>
        /// Gets or sets the referral URL.
        /// </summary>
        /// <value>
        /// The referral URL.
        /// </value>
        public string ReferralUrl { get; set; }

        /// <summary>
        /// Gets the nameservers.
        /// </summary>
        /// <value>
        /// The nameservers.
        /// </value>
        public IList<string> Nameservers { get; private set; }

        /// <summary>
        /// Gets or sets the modified date.
        /// </summary>
        /// <value>
        /// The modified date.
        /// </value>
        public DateTime ModifiedDate { get; set; }

        /// <summary>
        /// Gets or sets the created date.
        /// </summary>
        /// <value>
        /// The created date.
        /// </value>
        public DateTime CreatedDate { get; set; }

        /// <summary>
        /// Gets or sets the expiration date.
        /// </summary>
        /// <value>
        /// The expiration date.
        /// </value>
        public DateTime ExpirationDate { get; set; }
    }
}
