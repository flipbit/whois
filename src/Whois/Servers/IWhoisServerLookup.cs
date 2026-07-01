using System;
using System.Threading.Tasks;

namespace Whois.Servers
{
    /// <summary>
    /// Interface to lookup the appropriate root WHOIS server for a given request.
    /// </summary>
    public interface IWhoisServerLookup : IDisposable
    {
        /// <summary>
        /// Lookups the root WHOIS server for the specified request.
        /// </summary>
        WhoisResponse Lookup(WhoisRequest request);

        /// <summary>
        /// Lookups the root WHOIS server for the specified request.
        /// </summary>
        Task<WhoisResponse> LookupAsync(WhoisRequest request);
    }
}