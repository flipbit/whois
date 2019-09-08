using System;
using System.Collections.Generic;

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
            NameServers = new List<string>();
            DomainStatus = new List<string>();
        }

        public string Content { get; set; }

        public WhoisResponseStatus Status { get; set; }

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
        /// Gets or sets the billing contact
        /// </summary>
        public Contact BillingContact { get; set; }

        /// <summary>
        /// Gets the domain name servcers
        /// </summary>
        public IList<string> NameServers { get; }

        public IList<string> DomainStatus { get; }

        public string DnsSecStatus { get; set; }

        public Trademark Trademark { get; set; }

        public int FieldsParsed { get; set; }

        public int ParsingErrors { get; set; }

        public string TemplateName { get; set; }

        public string Remarks { get; set; }

        public WhoisServer RootServer { get; set; }

        public WhoisResponse Referrer { get; set; }

        internal WhoisResponse ChainReferrer(WhoisResponse response)
        {
            response.Referrer = this;

            return response;
        }

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