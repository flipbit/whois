using System.Collections;
using System.Text;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois
{
    /// <summary>
    /// Class to lookup a WHOIS server for a given domain name.
    /// </summary>
    public class IanaServerLookup : IWhoisServerLookup
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisServerLookup
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current WhoisServerLookup.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>
        /// The TCP reader factory.
        /// </value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerLookup"/> class.
        /// </summary>
        public IanaServerLookup(): this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerLookup"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public IanaServerLookup(Encoding encoding)
        {
            CurrentEncoding = encoding;
        }

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
            // IANA WHOIS Server
            var server = "whois.iana.org";

            //var tld = GetTld(domain);
            var tld = domain;

            ArrayList result;

            using (var tcpReader = TcpReaderFactory.Create(CurrentEncoding))
            {
                result = tcpReader.Read(server, 43, tld);
            }

            return result.AsString();
        }
    }
}