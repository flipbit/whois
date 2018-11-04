using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Whois.Models;

namespace Whois.Servers
{
    /// <summary>
    /// Class to lookup a WHOIS server for a given domain name.
    /// </summary>
    public class InternicServerLookup : IWhoisServerLookup
    {
        /// <summary>
        /// Lookups the WHOIS server for the specified TLD.
        /// </summary>
        public WhoisServer Lookup(string tld)
        {
            return AsyncHelper.RunSync(() => LookupAsync(tld));
        }

        public async Task<WhoisServer> LookupAsync(string tld)
        {
            // This is the default WHOIS server
            var server = "whois.internic.net";

            // Hack for TK domains
            if (tld == "tk")
            {
                return new WhoisServer(tld, "whois.dot.tk");
            }

            var whoisServerName = tld + '.' + "whois-servers.net";

            try
            {
                var hostEntry = await Dns.GetHostEntryAsync(whoisServerName);

                server = hostEntry.HostName == whoisServerName ? "whois.internic.net" : hostEntry.HostName;
            }
            catch (SocketException ex)
            {
                throw new WhoisException("WHOIS server lookup fail for TLD: " + tld, ex);
            }

            return new WhoisServer(tld, server);
        }
    }
}