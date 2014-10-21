using System.Text;
using Whois.Domain;

namespace Whois.Servers
{
    /// <summary>
    /// Interface to lookup the appropriate WHOIS server for a given domain
    /// </summary>
    public interface IWhoisServerLookup
    {
        /// <summary>
        /// Lookups the WHOIS server for the specified domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        IWhoisServer Lookup(string domain);
    }
}