using System.Threading.Tasks;
using Whois.Models;

namespace Whois.Servers
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisServerLookup : IWhoisServerLookup
    {
        public WhoisServer Lookup(string domain)
        {
            return new WhoisServer("com", "test.whois.com");
        }

        public Task<WhoisServer> LookupAsync(string tld)
        {
            return Task.FromResult(Lookup(tld));
        }
    }
}
