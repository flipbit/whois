using System;
using System.Text;
using Whois.Interfaces;
using Whois.Net;
using Whois.Servers;

namespace Whois.Visitors
{
    /// <summary>
    /// Downloads WHOIS information from the specified WHOIS server
    /// </summary>
    public class DownloadVisitor : IWhoisVisitor
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
        /// Gets or sets the whois server lookup.
        /// </summary>
        /// <value>
        /// The whois server lookup.
        /// </value>
        public IWhoisServerLookup WhoisServerLookup { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DownloadVisitor"/> class.
        /// </summary>
        public DownloadVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DownloadVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public DownloadVisitor(Encoding encoding)
        {
            TcpReaderFactory = new TcpReaderFactory();
            WhoisServerLookup = new IanaServerLookup();

            Encoding = encoding;
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            if (record.Server == null)
            {
                throw new ArgumentException("Given WhoisRecord does not have the Server property set");
            }

            using (var tcpReader = TcpReaderFactory.Create(Encoding))
            {
                record.Text = tcpReader.Read(record.Server.Url, 43, record.Domain);
            }

            return record;
        }
    }
}