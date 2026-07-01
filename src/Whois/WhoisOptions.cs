using System.Text;

namespace Whois
{
    /// <summary>
    /// Specifies default options for looking up WHOIS information
    /// </summary>
    public class WhoisOptions
    {
        public static WhoisOptions Defaults { get; }

        static WhoisOptions()
        {
            Defaults = new WhoisOptions
            {
                Encoding = Encoding.UTF8,
                FollowReferrer = true,
                TimeoutSeconds = 10
            };
        }

        /// <summary>
        /// The default encoding to use.
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Defines the network timeout to use when communicating with servers.
        /// </summary>
        public int TimeoutSeconds { get; set; }

        /// <summary>
        /// Determines whether to following referral links when downloading WHOIS data.
        /// </summary>
        public bool FollowReferrer { get; set; }

        /// <summary>
        /// Clones this instance.
        /// </summary>
        public WhoisOptions Clone()
        {
            return new WhoisOptions
            {
                Encoding = Encoding,
                TimeoutSeconds = TimeoutSeconds,
                FollowReferrer = FollowReferrer
            };
        }
    }
}
