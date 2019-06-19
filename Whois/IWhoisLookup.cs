using System.Text;
using System.Threading.Tasks;
using Tokens.Transformers;
using Tokens.Validators;
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

        /// <summary>
        /// Add a Tokenizer template to parse the WHOIS response with.
        /// </summary>
        void AddTemplate(string content, string name);

        /// <summary>
        /// Clears all the registered Tokenizer WHOIS parsing templates.
        /// </summary>
        void ClearTemplates();

        /// <summary>
        /// Registers a WHOIS transformer.
        /// </summary>
        void RegisterTransformer<T>() where T : ITokenTransformer;

        /// <summary>
        /// Registers a WHOIS validator.
        /// </summary>
        void RegisterValidator<T>()  where T : ITokenValidator;
    }
}
