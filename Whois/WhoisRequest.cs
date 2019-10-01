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
            Encoding = WhoisOptions.Defaults.DefaultEncoding;
            TimeoutSeconds = WhoisOptions.Defaults.TimeoutSeconds;
            FollowReferrer = true;
        }

        /// <summary>
        /// Creates a request for the given query with the default options
        /// </summary>
        /// <param name="query"></param>
        public WhoisRequest(string query) : this()
        {
            Query = query;
        }

        /// <summary>
        /// The WHOIS query, typically the domain name
        /// </summary>
        public string Query { get; set; }

        /// <summary>
        /// The encoding to use whilst reading data from the WHOIS server
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// The network timeout to use whilst reading data from the WHOIS server
        /// </summary>
        public int TimeoutSeconds { get; set; }

        /// <summary>
        /// Is true, then referral links within WHOIS responses will be followed.
        /// </summary>
        public bool FollowReferrer { get; set; }

        //public string WhoisServerUrl { get; set; }
    }
}
