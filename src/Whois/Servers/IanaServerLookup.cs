using System;
using System.Threading.Tasks;
using Tokens;
using Whois.Logging;
using Whois.Net;
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

        private readonly Lazy<TokenMatcher> ianaTemplate;
        private readonly ResourceReader resourceReader;

        /// <summary>
        /// The <see cref="ITcpReader"/> to use for network requests
        /// </summary>
        public ITcpReader TcpReader { get; set; }

        /// <summary>
        /// Creates a new instance of the IANA Server Lookup
        /// </summary>
        public IanaServerLookup() : this(new TcpReader())
        {
        }

        public IanaServerLookup(ITcpReader tcpReader)
        {
            ianaTemplate = new Lazy<TokenMatcher>(CreateIanaTemplate);
            resourceReader = new ResourceReader();
            TcpReader = tcpReader;
        }
        

        public WhoisResponse Lookup(WhoisRequest request)
        {
            return AsyncHelper.RunSync(() => LookupAsync(request));
        }

        public async Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            var tld = GetTld(request.Query);

            var content = await Download(tld, request);

            // Reflect the raw response onto a ParsedWhoisServer object
            var matcher = ianaTemplate.Value;
            var result = matcher.Match<WhoisResponse>(content);

            if (result.Success)
            {
                var match = result.BestMatch.Value;

                match.Content = content;

                return match;
            }

            return new WhoisResponse
            {
                Content = content,
                DomainName = new HostName(tld), 
                Status = WhoisStatus.Unknown
            };
        }

        private async Task<string> Download(string tld, WhoisRequest request)
        {
            Log.Debug("Looking up Root TLD server for {0} from {1}", tld, IanaUrl);

            var response = await TcpReader.Read(IanaUrl, 43, tld.ToUpper(), request.Encoding, request.TimeoutSeconds);

            Log.Debug("Received {0:###,###,##0} byte(s).", response.Length);

            return response;
        }

        private TokenMatcher CreateIanaTemplate()
        {
            var matcher = new TokenMatcher();
            matcher.RegisterTransformer<CleanDomainStatusTransformer>();
            matcher.RegisterTransformer<ToHostNameTransformer>();

            var resourceNames = resourceReader.GetNames("whois.iana.org");

            foreach (var resourceName in resourceNames)
            {
                var content = resourceReader.GetContent(resourceName);
            
                matcher.RegisterTemplate(content);
            }
            
            return matcher;
        }

        private string GetTld(string domain)
        {
            var tld = domain;

            if (!string.IsNullOrEmpty(domain))
            {
                var parts = domain.Split('.');

                if (parts.Length > 1) tld = parts[parts.Length - 1];
            }

            return tld;
        }

        public void Dispose()
        {
            TcpReader?.Dispose();
        }
    }
}