using System;
using System.Collections.Generic;
using Whois.Models;

namespace Whois
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
            NameServers = new List<string>();
            DomainStatus = new List<string>();
        }

        /// <summary>
        /// Contains the raw response returned from the WHOIS server
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Returns the status of this WHOIS lookup
        /// </summary>
        public WhoisStatus Status { get; set; }

        /// <summary>
        /// Gets the domain name
        /// </summary>
        public string DomainName { get; set; }

        /// <summary>
        /// Gets the registry Domain Id
        /// </summary>
        public string RegistryDomainId { get; set; }

        /// <summary>
        /// Gets the domain name statuses
        /// </summary>
        public IList<string> DomainStatus { get; }

        /// <summary>
        /// Gets or sets the date the domain was registered.
        /// </summary>
        public DateTime? Registered { get; set; }

        /// <summary>
        /// Gets or sets the date the domain was last updated
        /// </summary>
        public DateTime? Updated { get; set; }

        /// <summary>
        /// Gets or sets the expiration date of the domain
        /// </summary>
        public DateTime? Expiration { get; set; }

        /// <summary>
        /// Gets or sets the registrar
        /// </summary>
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
        /// Gets or sets the billing contact
        /// </summary>
        public Contact BillingContact { get; set; }

        /// <summary>
        /// Gets or sets the zone contact
        /// </summary>
        public Contact ZoneContact { get; set; }

        /// <summary>
        /// Gets the domain name servers
        /// </summary>
        public IList<string> NameServers { get; }

        /// <summary>
        /// Contains any remarks about the domain registration
        /// </summary>
        public string Remarks { get; set; }

        /// <summary>
        /// Contains the DNS Sec status
        /// </summary>
        public string DnsSecStatus { get; set; }

        /// <summary>
        /// Contains any trademark information about this registration
        /// </summary>
        public Trademark Trademark { get; set; }

        /// <summary>
        /// The number of fields parsed from the raw WHOIS response
        /// </summary>
        public int FieldsParsed { get; set; }

        /// <summary>
        /// The number of parsing errors that occured whilst parsing this WHOIS response
        /// </summary>
        public int ParsingErrors { get; set; }

        /// <summary>
        /// The template that was used to parse this WHOIS response
        /// </summary>
        public string TemplateName { get; set; }

        /// <summary>
        /// The referring WHOIS server, if any
        /// </summary>
        public WhoisResponse Referrer { get; set; }

        /// <summary>
        /// Sets the WHOIS referrer on this instance
        /// </summary>
        internal WhoisResponse ChainReferrer(WhoisResponse response)
        {
            response.Referrer = this;

            return response;
        }

        /// <summary>
        /// Determines if the given WHOIS server URL has been visited in this lookup chain
        /// </summary>
        internal bool SeenServer(string whoisServerUrl)
        {
            if (Registrar != null && string.Compare(Registrar.WhoisServerUrl, whoisServerUrl, StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                return true;
            }

            if (Referrer == null) return false;

            return Referrer.SeenServer(whoisServerUrl);
        }
    }
}