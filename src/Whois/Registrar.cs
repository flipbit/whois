namespace Whois
{
    /// <summary>
    /// Represents a Domain Name registrar
    /// </summary>
    public class Registrar
    {
        /// <summary>
        /// The name of he Registrar
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The Registrar's IANA Number, if available
        /// </summary>
        public string IanaId { get; set; }

        /// <summary>
        /// The URL of the Registrar's website
        /// </summary>
        public string Url { get; set; }

        /// <summary>
        /// The Abuse contact email
        /// </summary>
        public string AbuseEmail { get; set; }

        /// <summary>
        /// The Abuse contact telephone number
        /// </summary>
        public string AbuseTelephoneNumber { get; set; }

        /// <summary>
        /// The Hostname of the Registrar's WHOIS server
        /// </summary>
        public HostName WhoisServer { get; set; }
    }
}
