using System.Text;
using Whois.Domain;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Expands the WHOIS results if needed to.
    /// </summary>
    public class ExpandResultsVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>The TCP reader factory.</value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExpandResultsVisitor"/> class.
        /// </summary>
        public ExpandResultsVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExpandResultsVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public ExpandResultsVisitor(Encoding encoding)
        {
            TcpReaderFactory = new TcpReaderFactory();

            CurrentEncoding = encoding;
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            // Check to narrow down search results
            if (record.Text.AsString().Contains("=xxx"))
            {
                using (var tcpReader = TcpReaderFactory.Create(CurrentEncoding))
                {
                    record.Text = tcpReader.Read(record.Server, 43, "=" + record.Domain);
                }
            }
            return record;
        }
    }
}