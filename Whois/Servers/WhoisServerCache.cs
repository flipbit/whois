using System.Collections.Concurrent;

namespace Whois.Servers
{
    /// <summary>
    /// Simple thread-safe in-memory WHOIS server cache
    /// </summary>
    public class WhoisServerCache
    {
        private readonly ConcurrentDictionary<string, WhoisResponse> cache;

        public WhoisServerCache()
        {
            cache = new ConcurrentDictionary<string, WhoisResponse>();
        }

        public WhoisResponse Get(string tld)
        {
            return cache.TryGetValue(tld, out var server) ? server : null;
        }

        public void Set(WhoisResponse server)
        {
            cache.AddOrUpdate(server.DomainName.ToUnicodeString(), server, (tld, existing) => server);
        }
    }
}
