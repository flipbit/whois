using System.Text;
using System.Threading.Tasks;
using Whois.Logging;
using Whois.Models;
using Whois.Servers;

namespace Whois.Visitors
{
    /// <summary>
    /// Gets the WHOIS server for a given domain.
    /// </summary>
    public class WhoisServerVisitor : IWhoisVisitor
    {
        private static readonly ILog Log = LogProvider.GetCurrentClassLogger();

        public WhoisServerCache Cache { get; set; }

        public IWhoisServerLookup WhoisServerLookup { get; set; }

        public WhoisServerVisitor()
        {
            Cache = new WhoisServerCache();
            WhoisServerLookup = new IanaServerLookup();
        }

        public async Task<LookupState> Visit(LookupState state)
        {
            var server = Cache.Get(state.Tld);

            if (server == null)
            {
                server = await WhoisServerLookup.LookupAsync(state.Tld);

                if (server != null)
                {
                    Cache.Set(server);
                }
            }
            else
            {
                Log.Debug("Retreived Root WHOIS server for TLD {0} from cache.", state.Tld);
            }

            if (server == null || string.IsNullOrEmpty(server.Url))
            {
                Log.Error("Unable to locate Root WHOIS server for TLD: {0}", state.Tld);
                throw new WhoisException($"Unable to locate Root WHOIS server for TLD: {state.Tld}");
            }

            state.WhoisServer = server;

            return state;
        }
    }
}