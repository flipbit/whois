using System.Threading.Tasks;
using Whois.Models;

namespace Whois.Servers
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisServerLookup : IWhoisServerLookup
    {
        public WhoisResponse Lookup(string domain)
        {
            return new WhoisResponse {DomainName = "com", Registrar = new Registrar {WhoisServerUrl = "test.whois.com"}};
        }

        public Task<WhoisResponse> LookupAsync(string tld)
        {
            return Task.FromResult(Lookup(tld));
        }
    }
}
