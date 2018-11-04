using System.Text;

namespace Whois
{
    /// <summary>
    /// Specifies options for looking up WHOIS information
    /// </summary>
    public class WhoisOptions
    {
        public static WhoisOptions Defaults { get; }

        static WhoisOptions()
        {
            Defaults = new WhoisOptions
            {
                DefaultEncoding = Encoding.UTF8,
                ParseWhoisResponse = true,
                ThrowOnParsingException = true
            };
        }

        /// <summary>
        /// The default encoding to use.
        /// </summary>
        public Encoding DefaultEncoding { get; set; }

        /// <summary>
        /// Determines whether to parse the WHOIS response into a <see cref="ParseWhoisResponse"/> object.
        /// </summary>
        public bool ParseWhoisResponse { get; set; }

        /// <summary>
        /// Determines whether an exception is thrown is WHOIS parsing fails.
        /// </summary>
        public bool ThrowOnParsingException { get; set; }

        public WhoisOptions Clone()
        {
            return new WhoisOptions
            {
                DefaultEncoding = DefaultEncoding,
                ParseWhoisResponse = ParseWhoisResponse,
                ThrowOnParsingException = ThrowOnParsingException
            };
        }
    }
}
