using System.Text;
using Whois.Interfaces;
using Whois.Net;
using Whois.Tokens;

namespace Whois.Visitors
{
    /// <summary>
    /// Visitor to detect and redirect WHOIS queries to registrar specific WHOIS servers.
    /// </summary>
    public class RedirectVisitor : IWhoisVisitor
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
        public Encoding Encoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RedirectVisitor"/> class.
        /// </summary>
        public RedirectVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RedirectVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public RedirectVisitor(Encoding encoding)
        {
            // You should use an IoC container to do this.
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
            var referralIndex = record.Text.IndexOf(": " + record.Domain);

            if (referralIndex > -1)
            {
                //var whoIsServer = record.Text.Containing("whois", referralIndex);

                //whoIsServer = whoIsServer.SubstringAfterChar(":").Trim();

                //if (!string.IsNullOrEmpty(whoIsServer))
                //{
                //    using (var tcpReader = TcpReaderFactory.Create(Encoding))
                //    {
                //        record.Text = tcpReader.Read(whoIsServer, 43, record.Domain);
                //    }
                //}
            }

            return record;
        }

        /// <summary>
        /// Determines whether a WHOIS record is a redirect record to another WHOIS server.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <param name="redirect">The redirect.</param>
        /// <returns></returns>
        public bool IsARedirectRecord(WhoisRecord record, out WhoisRedirect redirect)
        {
            var isARedirectRecord = false;

            redirect = null;

            if (record.Text.Contains("many different competing registrars"))
            {
                var reader = new EmbeddedPatternReader();
                var pattern = reader.Read(GetType().Assembly, "Whois.Patterns.Redirects.Iana.txt");

                var tokenizer = new Tokenizer();

                var text = record.Text.Split('\n');

                var tokenResult = tokenizer.Parse<WhoisRedirect>(pattern, text);

                redirect = tokenResult.Value;

                isARedirectRecord = true;
            }


            return isARedirectRecord;
        }
    }
}