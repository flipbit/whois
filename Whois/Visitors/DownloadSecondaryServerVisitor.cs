using System.Text;
using Whois.Domain;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Expands the WHOIS results if needed to.
    /// </summary>
    public class DownloadSecondaryServerVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>The TCP reader factory.</value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DownloadSecondaryServerVisitor"/> class.
        /// </summary>
        public DownloadSecondaryServerVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DownloadSecondaryServerVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public DownloadSecondaryServerVisitor(Encoding encoding)
        {
            // You should use an IoC container to do this.
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
            var referralIndex = record.Text.IndexOfLineEndingWith(": " + record.Domain);

            if (referralIndex > -1)
            {
                var whoIsServer = record.Text.Containing("whois", referralIndex);

                whoIsServer = whoIsServer.SubstringAfterChar(":").Trim();

                if (!string.IsNullOrEmpty(whoIsServer))
                {
                    using (var tcpReader = TcpReaderFactory.Create(CurrentEncoding))
                    {
                        record.Text = tcpReader.Read(whoIsServer, 43, record.Domain);
                    }
                }
            }

            return record;
        }
    }
}