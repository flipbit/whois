using Whois.Models;

namespace Whois
{
    public class LookupState
    {
        public string Domain { get; set; }

        public string Tld { get; set; }

        public WhoisServer WhoisServer { get; set; }

        public WhoisOptions Options { get; set; }

        public WhoisResponse Response { get; set; }
    }
}
