using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Tokens.Transformers;
using Tokens.Validators;

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
        Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default);

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Registers a Tokenizer validator with the WHOIS parser.
        /// </summary>
        void RegisterValidator<T>() where T : ITokenValidator;

        /// <summary>
        /// Registers a Tokenizer transformer with the WHOIS parser.
        /// </summary>
        void RegisterTransformer<T>() where T : ITokenTransformer;
    }
}
