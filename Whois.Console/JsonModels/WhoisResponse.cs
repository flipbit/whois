using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;

namespace Whois.JsonModels
{
    public class WhoisResponse
    {
        public WhoisResponse()
        {
        }

        public WhoisResponse(Whois.WhoisResponse response)
        {
            DomainName = response.DomainName.ToString();
            RegistryDomainId = response.RegistryDomainId;
            Registered = response.Registered;
            Updated = response.Updated;
            Expiration = response.Expiration;
            if (response.Registrant != null) Registrant = new Contact(response.Registrant);
            if (response.TechnicalContact != null) TechnicalContact = new Contact(response.TechnicalContact);
            if (response.AdminContact != null) AdminContact = new Contact(response.AdminContact);
            if (response.Registrar != null) Registrar = new Registrar(response.Registrar);
            if (response.NameServers != null && response.NameServers.Any()) NameServers = response.NameServers;
            if (response.DomainStatus != null && response.DomainStatus.Any()) DomainStatus = response.DomainStatus;
            DnsSecStatus = response.DnsSecStatus;
        }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string DomainName { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string RegistryDomainId { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public DateTime? Registered { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public DateTime? Updated { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public DateTime? Expiration { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Registrar Registrar { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Contact Registrant { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Contact TechnicalContact { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Contact AdminContact { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IList<string> NameServers { get; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IList<string> DomainStatus { get; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string DnsSecStatus { get; set; }
    }
}
