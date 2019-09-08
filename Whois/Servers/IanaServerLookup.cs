using System;
using System.Text;
using System.Threading.Tasks;
using Whois.Net;
using Tokens;
using Whois.Logging;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Servers
{
    /// <summary>
    /// Class to lookup a WHOIS server for a TLD from IANA 
    /// </summary>
    public class IanaServerLookup : IWhoisServerLookup
    {
        private const string IanaUrl = "whois.iana.org";
        
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        private Lazy<TokenMatcher> ianaTemplate;
        private ResourceReader resourceReader;

        /// <summary>
        /// Creates a new instance of the IANA Server Lookup
        /// </summary>
        public IanaServerLookup()
        {
            ianaTemplate = new Lazy<TokenMatcher>(CreateIanaTemplate);
            resourceReader = new ResourceReader();
        }
        

        public WhoisServer Lookup(string tld)
        {
            return LookupAsync(tld).Result;
        }

        public async Task<WhoisServer> LookupAsync(string tld)
        {            
            var content = await GetWhoisServerResponse(tld);

            // Reflect the raw response onto a ParsedWhoisServer object
            var matcher = ianaTemplate.Value;
            var result = matcher.Match<WhoisResponse>(content);

            if (result.Success)
            {
                var match = result.BestMatch.Value;

                return new WhoisServer
                {
                    AdminContact = match.AdminContact,
                    Changed = match.Updated,
                    Content = content,
                    Created = match.Registered,
                    NameServers = match.NameServers,
                    Status = match.Status,
                    TechContact = match.TechnicalContact,
                    Tld = match.DomainName,
                    Url = match.Registrar?.WhoisServerUrl,
                    Remarks = match.Remarks,
                    Organization = new Organization
                    {
                        Name = match.Registrant?.Organization,
                        Address = match.Registrant?.Address
                    }
                };
            }

            return new WhoisServer { Tld = tld, Status = WhoisResponseStatus.Unknown };
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

        private TokenMatcher CreateIanaTemplate()
        {
            var matcher = new TokenMatcher();
            matcher.RegisterTransformer<CleanDomainStatusTransformer>();

            var resourceNames = resourceReader.GetNames("whois.iana.org");

            foreach (var resourceName in resourceNames)
            {
                var content = resourceReader.GetContent(resourceName);
            
                matcher.RegisterTemplate(content);
            }
            
            return matcher;
        }
    }
}