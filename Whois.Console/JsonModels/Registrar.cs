using Newtonsoft.Json;

namespace Whois.JsonModels
{
    public class Registrar
    {
        public Registrar(Whois.Registrar registrar)
        {
            Name = registrar.Name;
            IanaId = registrar.IanaId;
            Url = registrar.Url;
            AbuseEmail = registrar.AbuseEmail;
            AbuseTelephoneNumber = registrar.AbuseTelephoneNumber;
            WhoisServer = registrar.WhoisServer;
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
        public HostName WhoisServer { get; set; }
    }
}
