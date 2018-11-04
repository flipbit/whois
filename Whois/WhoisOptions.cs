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
                DefaultEncoding = Encoding.UTF8
            };
        }

        /// <summary>
        /// The default encoding to use
        /// </summary>
        public Encoding DefaultEncoding { get; set; }

        public WhoisOptions Clone()
        {
            return new WhoisOptions
            {
                DefaultEncoding = DefaultEncoding
            };
        }
    }
}
