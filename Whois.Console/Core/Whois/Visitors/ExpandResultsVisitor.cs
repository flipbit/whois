using Flipbit.Core.Whois.Arrays;
using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;

namespace Flipbit.Core.Whois.Visitors
{
    /// <summary>
    /// Expands the WHOIS results if needed to.
    /// </summary>
    public class ExpandResultsVisitor : IWhoisVisitor
    {
                 /// <summary>
        /// Gets or sets the TCP reader factory.
        /// </summary>
        /// <value>The TCP reader factory.</value>
        public ITcpReaderFactory TcpReaderFactory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ExpandResultsVisitor"/> class.
        /// </summary>
        public ExpandResultsVisitor()
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
            // Check to narrow down search results
            if (record.Text.AsString().Contains("=xxx"))
            {
                using (var tcpReader = TcpReaderFactory.Create())
                {
                    record.Text= tcpReader.Read(record.Server, 43, "=" + record.Domain);
                }
            }
            return record;
        }
    }
}