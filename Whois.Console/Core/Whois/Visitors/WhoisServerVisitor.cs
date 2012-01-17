using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois.Visitors
{
    /// <summary>
    /// Gets the WHOIS server for a given domain.
    /// </summary>
    public class WhoisServerVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets or sets the whois server lookup.
        /// </summary>
        /// <value>The whois server lookup.</value>
        public IWhoisServerLookup WhoisServerLookup { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerVisitor"/> class.
        /// </summary>
        public WhoisServerVisitor()
        {
            WhoisServerLookup = new WhoisServerLookup();
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            record.Server = WhoisServerLookup.Lookup(record.Domain);

            return record;
        }
    }
}