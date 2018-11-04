using System;
using System.Collections.Generic;

namespace Whois.Models
{
    /// <summary>
    /// Represents WHOIS information for a domain.
    /// </summary>
    public class ParsedWhoisResponse 
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisResponse"/> class.
        /// </summary>
        public ParsedWhoisResponse()
        {
            NameServers = new List<string>();
            DomainStatus = new List<string>();
        }

        public string DomainName { get; set; }

        public string RegistryDomainId { get; set; }

        /// <summary>
        /// Gets or sets the date the domain was registered.
        /// </summary>
        public DateTime? Registered { get; set; }

        public DateTime? Updated { get; set; }

        public DateTime? Expiration { get; set; }

        public Registrar Registrar { get; set; }

        /// <summary>
        /// Gets or sets the registrant.
        /// </summary>
        public Contact Registrant { get; set; }

        /// <summary>
        /// Gets or sets the technical contact.
        /// </summary>
        public Contact TechnicalContact { get; set; }

        /// <summary>
        /// Gets or sets the admin contact.
        /// </summary>
        public Contact AdminContact { get; set; }

        /// <summary>
        /// Gets the domain name servcers
        /// </summary>
        public IList<string> NameServers { get; }

        public IList<string> DomainStatus { get; }

        public string DnsSecStatus { get; set; }
    }
}