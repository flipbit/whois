using System.Text;

namespace Whois.Interfaces
{
    /// <summary>
    /// Interface to lookup the appropriate WHOIS server for a given domain
    /// </summary>
    public interface IWhoisServerLookup
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisServerLookup
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current WhoisServerLookup.</returns>
        Encoding CurrentEncoding { get; }

        /// <summary>
        /// Lookups the WHOIS server for the specified domain.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        string Lookup(string domain);
    }
}