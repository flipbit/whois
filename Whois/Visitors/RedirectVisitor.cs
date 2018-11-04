using System.Threading.Tasks;
using Whois.Net;
using Tokens;
using Whois.Logging;
using Whois.Models;
using Whois.Resources;

namespace Whois.Visitors
{
    /// <summary>
    /// Visitor to detect and redirect WHOIS queries to registrar specific WHOIS servers.
    /// </summary>
    public class RedirectVisitor : IWhoisVisitor
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        public async Task<LookupState> Visit(LookupState state)
        {
            if (IsARedirectRecord(state.Response, out var redirect))
            {
                using (var tcpReader = TcpReaderFactory.Create())
                {
                    var response = await tcpReader.Read(redirect.Url, 43, state.Domain, state.Options.DefaultEncoding);

                    Log.Debug("Lookup {0}: Downloaded {1:###,###,##0} byte(s) from {2}.", state.Domain, response.Length, redirect.Url);

                    state.Response = new WhoisResponse
                    {
                        Domain = state.Domain,
                        Content = response
                    };
                }
            }

            return state;
        }

        /// <summary>
        /// Determines whether a WHOIS response is a redirect response to another WHOIS server.
        /// </summary>
        public bool IsARedirectRecord(WhoisResponse response, out WhoisRedirect redirect)
        {
            redirect = null;

            var pattern = Embedded.Patterns.Redirects.VerisignGrs; 

            var tokenizer = new TokenMatcher();
            tokenizer.AddPattern(pattern, "verisign-grs.com");

            if (tokenizer.TryMatch<WhoisRedirect>(response.Content, out var match))
            {
                Log.Debug("Found redirect for {0} to {1}", response.Domain, match.Result.Url);

                redirect = match.Result;

                if (string.IsNullOrEmpty(redirect.Url) == false)
                {
                    return true;
                }
            }

            return false;
        }
    }
}