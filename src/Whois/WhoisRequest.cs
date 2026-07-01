using System.Text;

namespace Whois
{
    /// <summary>
    ///  Represents a request to query WHOIS information
    /// </summary>
    public class WhoisRequest
    {
        /// <summary>
        /// Creates an empty query with the default options
        /// </summary>
        public WhoisRequest()
        {
        }

        /// <summary>
        /// Creates a request for the given query with the default options
        /// </summary>
        public WhoisRequest(string query)
        {
            Query = query;
        }

        /// <summary>
        /// The WHOIS query, typically the domain name
        /// </summary>
        public string Query { get; set; } = string.Empty;

        /// <summary>
        /// The encoding to use whilst reading data from the WHOIS server
        /// </summary>
        public Encoding Encoding { get; set; } = Encoding.UTF8;

        /// <summary>
        /// The network timeout to use whilst reading data from the WHOIS server
        /// </summary>
        public int TimeoutSeconds { get; set; } = 10;

        /// <summary>
        /// Is true, then referral links within WHOIS responses will be followed.
        /// </summary>
        public bool FollowReferrer { get; set; } = true;

        /// <summary>
        /// If set, the given WHOIS server will be queried.  If blank, the WHOIS
        /// server for the domain TLD will be attempted to be found automatically.
        /// </summary>
        public string? WhoisServer { get; set; }
    }
}
