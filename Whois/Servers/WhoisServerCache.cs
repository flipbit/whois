using System.Collections.Concurrent;
using Whois.Models;

namespace Whois.Servers
{
    /// <summary>
    /// Simple thread-safe in-memory WHOIS server cache
    /// </summary>
    public class WhoisServerCache
    {
        private readonly ConcurrentDictionary<string, WhoisServer> cache;

        public WhoisServerCache()
        {
            cache = new ConcurrentDictionary<string, WhoisServer>();
        }

        public WhoisServer Get(string tld)
        {
            return cache.TryGetValue(tld, out var server) ? server : null;
        }

        public void Set(WhoisServer server)
        {
            cache.AddOrUpdate(server.Tld, server, (tld, existing) => server);
        }
    }
}
