using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tokens.Extensions;
using Tokens.Transformers;
using Tokens.Validators;
using Whois.Logging;
using Whois.Net;
using Whois.Parsers;
using Whois.Servers;

namespace Whois
{
    /// <summary>
    /// Looks up WHOIS information
    /// </summary>
    public class WhoisLookup : IWhoisLookup
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();
        
        private readonly WhoisParser whoisParser;

        /// <summary>
        /// The default <see cref="WhoisOptions"/> to use for this instance
        /// </summary>
        public WhoisOptions Options { get; set; }

        /// <summary>
        /// The WHOIS Server Lookup that finds root TLD servers for queries
        /// </summary>
        public IWhoisServerLookup ServerLookup { get; set; }

        /// <summary>
        /// The TCP reader that performs the network requests
        /// </summary>
        public ITcpReader TcpReader { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the default options
        /// </summary>
        public WhoisLookup() : this(WhoisOptions.Defaults.Clone())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class with the given <see cref="WhoisOptions"/>.
        /// </summary>
        public WhoisLookup(WhoisOptions options) 
        {
            Options = options;
            whoisParser = new WhoisParser();
            TcpReader = new TcpReader();
            ServerLookup = new IanaServerLookup(TcpReader);
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        public WhoisResponse Lookup(string domain)
        {
            return AsyncHelper.RunSync(() => LookupAsync(domain));
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        public WhoisResponse Lookup(string domain, Encoding encoding)
        {
            return AsyncHelper.RunSync(() => LookupAsync(domain, encoding));
        }

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        public WhoisResponse Lookup(WhoisRequest request)
        {
            return AsyncHelper.RunSync(() => LookupAsync(request));
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        public Task<WhoisResponse> LookupAsync(string domain)
        {
            return LookupAsync(domain, Options.Encoding);
        }

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        public Task<WhoisResponse> LookupAsync(string domain, Encoding encoding)
        {
            return LookupAsync(new WhoisRequest
            {
                Query = domain,
                Encoding = encoding,
                TimeoutSeconds = Options.TimeoutSeconds,
                FollowReferrer = Options.FollowReferrer
            });
        }

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        public async Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            if (string.IsNullOrEmpty(request.Query))
            {
                throw new ArgumentNullException("domain");
            }

            // Trim leading '.'
            if (request.Query.StartsWith(".")) request.Query = request.Query.Substring(1);

            // Validate domain name
            if (HostName.TryParse(request.Query, out var hostName) == false)
            {
                throw new WhoisException($"WHOIS Query Format Error: {request.Query}");
            }

            Log.Debug("Looking up WHOIS response for: {0}", hostName.Value);

            // Set our starting point
            WhoisResponse response;
            if (string.IsNullOrEmpty(request.WhoisServer))
            {
                // Lookup root WHOIS server for the TLD
                response = await ServerLookup.LookupAsync(request);
            }
            else
            {
                // Use the given WHOIS server
                response = WhoisResponse.WithServerUrl(request.WhoisServer);
            }

            // If query is for a top level domain, we're finished
            if (hostName.IsTld) return response;

            // Main loop: download & parse WHOIS data and follow the referrer chain
            var whoisServer = response?.WhoisServer;
            while (whoisServer != null)
            {
                // Download
                var content = await Download(whoisServer.Value, request);

                // Parse result
                var parsed = whoisParser.Parse(whoisServer.Value, content);

                // Sanity check: ensure the last response has some data
                if (parsed.FieldsParsed == 0 && response.FieldsParsed > 0)
                {
                    break;
                }

                // Build referrer chain
                response = response.Chain(parsed);

                // Check for referral loop
                if (request.FollowReferrer == false) break;
                if (response.SeenServer(response.WhoisServer)) break;
           
                // Lookup result in referral server
                whoisServer = response.WhoisServer;
            }

            return response;
        }

        public void RegisterValidator<T>() where T : ITokenValidator
        {
            whoisParser.RegisterValidator<T>();
        }

        public void RegisterTransformer<T>() where T : ITokenTransformer
        {
            whoisParser.RegisterTransformer<T>();
        }

        private async Task<string> Download(string url, WhoisRequest request)
        {
            // TODO: Expose this & extend for other TLDs
            var query = request.Query;
            if (query.EndsWith("jp")) query += "/e";    // Return English .jp results

            var content = await TcpReader.Read(url, 43, query, request.Encoding, request.TimeoutSeconds);

            Log.Debug("Lookup {0}: Downloaded {1:###,###,##0} byte(s) from {2}.", request.Query, content.Length, url);

            return content;
        }

        public void Dispose()
        {
            TcpReader?.Dispose();
        }
    }
}