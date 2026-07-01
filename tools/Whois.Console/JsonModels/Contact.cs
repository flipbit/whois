using System.Collections.Generic;
using Newtonsoft.Json;

namespace Whois.JsonModels
{
    public class Contact
    {
        public Contact()
        {
        }

        public Contact(Whois.Contact contact)
        {
            RegistryId = contact.RegistryId;
            Name = contact.Name;
            Organization = contact.Organization;
            Address = contact.Address;
            TelephoneNumber = contact.TelephoneNumber;
            TelephoneNumberExt = contact.TelephoneNumberExt;
            FaxNumber = contact.FaxNumber;
            FaxNumberExt = contact.FaxNumberExt;
            Email = contact.Email;
        }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string RegistryId { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Organization { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IList<string> Address { get;  }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string TelephoneNumber { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string TelephoneNumberExt { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string FaxNumber { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string FaxNumberExt { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Email { get; set; }
    }
}
