using System.Threading.Tasks;
using Whois.Models;

namespace Whois.Servers
{
    /// <summary>
    /// Fake class used for testing.
    /// </summary>
    internal class FakeWhoisServerLookup : IWhoisServerLookup
    {
        public WhoisResponse Lookup(WhoisRequest request)
        {
            return new WhoisResponse
            {
                DomainName = new HostName("com"), 
                Registrar = new Registrar
                {
                    WhoisServerUrl = "test.whois.com"
                }
            };
        }

        public Task<WhoisResponse> LookupAsync(WhoisRequest request)
        {
            return Task.FromResult(Lookup(request));
        }

        public void Dispose()
        {
        }
    }
}
