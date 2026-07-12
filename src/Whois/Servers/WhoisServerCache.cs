using System.Collections.Concurrent;

namespace Whois.Servers;

/// <summary>
/// Simple thread-safe in-memory WHOIS server cache
/// </summary>
public class WhoisServerCache
{
    private readonly ConcurrentDictionary<string, WhoisResponse> _cache;

    public WhoisServerCache()
    {
        _cache = new ConcurrentDictionary<string, WhoisResponse>();
    }

    public WhoisResponse? Get(string tld)
    {
        return _cache.TryGetValue(tld, out var server) ? server : null;
    }

    public void Set(WhoisResponse server)
    {
        _cache.AddOrUpdate(server.DomainName!.ToUnicodeString(), server, (tld, existing) => server);
    }
}
