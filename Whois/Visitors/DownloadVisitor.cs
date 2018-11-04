using System.Threading.Tasks;
using Whois.Logging;
using Whois.Models;
using Whois.Net;

namespace Whois.Visitors
{
    /// <summary>
    /// Downloads WHOIS information from the root WHOIS server
    /// </summary>
    public class DownloadVisitor : IWhoisVisitor
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        public async Task<LookupState> Visit(LookupState state)
        {
            using (var tcpReader = TcpReaderFactory.Create())
            {
                var response = await tcpReader.Read(state.WhoisServer.Url, 43, state.Domain, state.Options.DefaultEncoding);

                state.Response = new WhoisResponse
                {
                    Domain = state.Domain,
                    Content = response 
                };
            }

            Log.Debug("Lookup {0}: Downloaded {1:###,###,##0} byte(s) from {2}.", state.Domain, state.Response.Content.Length, state.WhoisServer.Url);

            return state;
        }
    }
}