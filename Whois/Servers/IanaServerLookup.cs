using System;
using System.Text;
using System.Threading.Tasks;
using Whois.Net;
using Tokens;
using Whois.Logging;
using Whois.Models;
using Whois.Resources;

namespace Whois.Servers
{
    /// <summary>
    /// Class to lookup a WHOIS server for a TLD from IANA 
    /// </summary>
    public class IanaServerLookup : IWhoisServerLookup
    {
        private const string IanaUrl = "whois.iana.org";
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        public WhoisServer Lookup(string tld)
        {
            return LookupAsync(tld).Result;
        }

        public async Task<WhoisServer> LookupAsync(string tld)
        {            
            var content = await GetWhoisServerResponse(tld);

            // Reflect the raw response onto a ParsedWhoisServer object
            var parsed = new Tokenizer()
                .Tokenize<ParsedWhoisServer>(Embedded.Patterns.Servers.Iana, content)
                .Value;

            var response = new WhoisServer(tld, parsed.Url);

            response.Content = content;
            response.ParsedWhoisServer = parsed;

            return response;
        }

        private async Task<string> GetWhoisServerResponse(string tld)
        {
            string response;

            Log.Debug("Looking up Root TLD server for {0} from {1}", tld, IanaUrl);

            using (var tcpReader = TcpReaderFactory.Create())
            {
                response = await tcpReader.Read(IanaUrl, 43, tld.ToUpper(), Encoding.UTF8);
            }

            Log.Debug("Received {0:###,###,##0} byte(s).", response.Length);

            return response;
        }
    }
}