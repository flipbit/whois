using System.Threading.Tasks;
using Whois.Models;

namespace Whois.Servers
{
    /// <summary>
    /// Interface to lookup the appropriate WHOIS server for a given TLD
    /// </summary>
    public interface IWhoisServerLookup
    {
        /// <summary>
        /// Lookups the WHOIS server for the specified TLD.
        /// </summary>
        WhoisServer Lookup(string tld);

        Task<WhoisServer> LookupAsync(string tld);
    }
}