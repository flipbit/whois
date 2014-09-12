using System.Text;
using Whois.Domain;
using Whois.Interfaces;

namespace Whois.Visitors
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
        /// Gets the current character encoding that the current TcpReader
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current reader.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerVisitor"/> class.
        /// </summary>
        public WhoisServerVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisServerVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public WhoisServerVisitor(Encoding encoding)
        {
            WhoisServerLookup = new WhoisServerLookup(encoding);

            CurrentEncoding = encoding;
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