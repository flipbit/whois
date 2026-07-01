using System.Text;

namespace Whois
{
    /// <summary>
    /// Specifies options for looking up WHOIS information
    /// </summary>
    public class WhoisOptions
    {
        /// <summary>
        /// The default encoding to use.
        /// </summary>
        public Encoding Encoding { get; set; } = Encoding.UTF8;

        /// <summary>
        /// Defines the network timeout to use when communicating with servers.
        /// </summary>
        public int TimeoutSeconds { get; set; } = 10;

        /// <summary>
        /// Determines whether to follow referral links when downloading WHOIS data.
        /// </summary>
        public bool FollowReferrer { get; set; } = true;
    }
}
