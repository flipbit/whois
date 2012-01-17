using Flipbit.Core.Whois.Arrays;
using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;
using Flipbit.Core.Whois.Strings;

namespace Flipbit.Core.Whois.Visitors
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
        /// Initializes a new instance of the <see cref="DownloadSecondaryServerVisitor"/> class.
        /// </summary>
        public DownloadSecondaryServerVisitor()
        {
            // You should use an IoC container to do this.
            TcpReaderFactory = new TcpReaderFactory();    
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

                using (var tcpReader = TcpReaderFactory.Create())
                {
                    record.Text = tcpReader.Read(whoIsServer, 43, record.Domain);
                }
            }

            return record;
        }
    }
}