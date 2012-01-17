using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois.Visitors
{
    /// <summary>
    /// Downloads WHOIS information from the specified WHOIS server
    /// </summary>
    public class DownloadVisitor : IWhoisVisitor
    {
         /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>The TCP reader factory.</value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DownloadVisitor"/> class.
        /// </summary>
        public DownloadVisitor()
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
            using (var tcpReader = TcpReaderFactory.Create())
            {
                record.Text = tcpReader.Read(record.Server, 43, record.Domain);
            }

            return record;
        }
    }
}