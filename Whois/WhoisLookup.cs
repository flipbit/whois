using System.Collections.Generic;
using System.Text;
using Whois.Domain;
using Whois.Interfaces;
using Whois.Visitors;

namespace Whois
{
    /// <summary>
    /// Looks up WHOIS information for a given domain.
    /// </summary>
    public class WhoisLookup
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisLookup
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current WhoisLookup.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Gets or sets the visitors.
        /// </summary>
        /// <value>The visitors.</value>
        public IList<IWhoisVisitor> Visitors { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class.
        /// </summary>
        public WhoisLookup() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisLookup"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public WhoisLookup(Encoding encoding)
        {
            CurrentEncoding = encoding;

            Visitors = new List<IWhoisVisitor>
                {
                    // Get initial WHOIS server URL
                    new WhoisServerVisitor(encoding),

                    // Download from initial server
                    new DownloadVisitor(encoding),

                    // Check to see if the results need to be expanded
                    new ExpandResultsVisitor(encoding),

                    // Check to see if a secondard WHOIS server needs to be queried
                    new DownloadSecondaryServerVisitor(encoding),

                    // UK domains
                    new NominetVisitor(encoding),

                    // MarkMonitor (e.g. Google)
                    new MarkMonitorVisitor(encoding),

                    // RIPN
                    new RipnVisitor(encoding),

                    // PT domains
                    new DnsPtVisitor(encoding),

                    // BR domains
                    new RegistroBrVisitor(encoding),
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