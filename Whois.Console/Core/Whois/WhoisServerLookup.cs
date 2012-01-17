using System;
using System.Net;
using System.Net.Sockets;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois
{
    /// <summary>
    /// Class to lookup a WHOIS server for a given domain name.
    /// </summary>
    public class WhoisServerLookup : IWhoisServerLookup
    {
        /// <summary>
        /// Gets the TLD for a given domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        public string GetTld(string domain)
        {
            var tld = string.Empty;

            if (!string.IsNullOrEmpty(domain))
            {
                var parts = domain.Split('.');

                if (parts.Length > 1) tld = parts[parts.Length - 1];
            }

            return tld;
        }

        /// <summary>
        /// Lookups the WHOIS server for the specified domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        public string Lookup(string domain)
        {
            // This is the default WHOIS server
            var server = "whois.internic.net";

            var tld = GetTld(domain);

            // Hack for TK domains
            if (tld == "tk")
            {
                server = "whois.dot.tk";
            }

            else if (!string.IsNullOrEmpty(tld))
            {
                var whoisServerName = tld + '.' + "whois-servers.net";

                try
                {
                    var hostEntry = Dns.GetHostEntry(whoisServerName);

                    server = hostEntry.HostName == whoisServerName ? "whois.internic.net" : hostEntry.HostName;
                }
                catch (SocketException ex)
                {
                    // You should throw an application exception really.
                    throw new ApplicationException("WHOIS server lookup failed for " + domain + ": " + ex.Message);
                }

            }

            return server;
        }
    }
}