using System.Collections.Generic;
using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;
using Flipbit.Core.Whois.Visitors;

namespace Flipbit.Core.Whois
{
    /// <summary>
    /// Looks up WHOIS information for a given domain.
    /// </summary>
    public class WhoisLookup
    {
        /// <summary>
        /// Gets or sets the visitors.
        /// </summary>
        /// <value>The visitors.</value>
        public IList<IWhoisVisitor> Visitors { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class.
        /// </summary>
        public WhoisLookup()
        {
            Visitors = new List<IWhoisVisitor>
                           {
                               new WhoisServerVisitor(),                // Get intial WHOIS server URL
                               new DownloadVisitor(),                   // Download from intial server

                               new ExpandResultsVisitor(),              // Check to see if the results need to be expanded
                               new DownloadSecondaryServerVisitor(),    // Check to see if a secondard WHOIS server needs to be queried

                               new NominetVisitor(),                    // UK domains
                               new MarkMonitorVisitor(),                // MarkMonitor (e.g. Google)
                               new RipnVisitor()                        // RIPN
                           };
        }


        /// <summary>
        /// Lookups the WHOIS information for the specified <see cref="domain"/>.
        /// </summary>
        /// <param name="domain">The domain.</param>
        /// <returns></returns>
        public WhoisRecord Lookup(string domain)
        {
            var record = new WhoisRecord { Domain = domain };

            foreach (var visitor in Visitors)
            {
                record = visitor.Visit(record);
            }

            return record;
        }
    }
}