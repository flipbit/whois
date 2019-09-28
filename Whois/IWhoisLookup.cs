using System.Text;
using System.Threading.Tasks;
using Whois.Models;

namespace Whois
{
    /// <summary>
    /// Represents a Lookup object that reads WHOIS information about domain and IP address registrations
    /// </summary>
    public interface IWhoisLookup
    {
        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        WhoisResponse Lookup(string domain);

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        WhoisResponse Lookup(string domain, Encoding encoding);

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        Task<WhoisResponse> LookupAsync(string domain);

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        Task<WhoisResponse> LookupAsync(string domain, Encoding encoding);
    }
}
