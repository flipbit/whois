using Newtonsoft.Json;

namespace Whois.JsonModels
{
    public class Registrar
    {
        public Registrar(Models.Registrar registrar)
        {
            Name = registrar.Name;
            IanaId = registrar.IanaId;
            Url = registrar.Url;
            AbuseEmail = registrar.AbuseEmail;
            AbuseTelephoneNumber = registrar.AbuseTelephoneNumber;
            WhoisServerUrl = registrar.WhoisServerUrl;
        }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Name { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string IanaId { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Url { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string AbuseEmail { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string AbuseTelephoneNumber { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string WhoisServerUrl { get; set; }
    }
}
