using System.Text;
using Whois.Interfaces;
using Whois.Net;

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
        public Encoding Encoding { get; private set; }

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

            Encoding = encoding;
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            // Check to narrow down search results
            if (record.Text.Contains("=xxx"))
            {
                using (var tcpReader = TcpReaderFactory.Create(Encoding))
                {
                    record.Text = tcpReader.Read(record.Server.Url, 43, "=" + record.Domain);
                }
            }
            return record;
        }
    }
}