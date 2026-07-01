using System;
using System.Text;
using System.Threading.Tasks;
using Tokens.Validators;
using Tokens.Transformers;

namespace Whois
{
    /// <summary>
    /// Represents a Lookup object that reads WHOIS information about domain and IP address registrations
    /// </summary>
    public interface IWhoisLookup : IDisposable
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
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        WhoisResponse Lookup(WhoisRequest request);

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain.
        /// </summary>
        Task<WhoisResponse> LookupAsync(string domain);

        /// <summary>
        /// Performs a WHOIS lookup on the specified domain with the given encoding.
        /// </summary>
        Task<WhoisResponse> LookupAsync(string domain, Encoding encoding);

        /// <summary>
        /// Performs a WHOIS lookup for the given request.
        /// </summary>
        Task<WhoisResponse> LookupAsync(WhoisRequest request);

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
