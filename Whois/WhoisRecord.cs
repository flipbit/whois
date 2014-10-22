using System;
using System.Collections.Generic;
using Whois.Servers;

namespace Whois
{
    /// <summary>
    /// Represents WHOIS information for a domain.
    /// </summary>
    public class WhoisRecord : ICloneable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisRecord"/> class.
        /// </summary>
        public WhoisRecord()
        {
            Nameservers = new List<string>();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisRecord"/> class.
        /// </summary>
        /// <param name="text">The text.</param>
        public WhoisRecord(string text)
        {
            Nameservers = new List<string>();

            Text = text;
        }

        public IEnumerable<string> AsStrings
        {
            get { return Text.Split('\n'); }
        }

        /// <summary>
        /// Gets or sets the text.
        /// </summary>
        /// <value>The text.</value>
        public string Text { get; set; }

        /// <summary>
        /// Gets or sets the domain.
        /// </summary>
        /// <value>The domain.</value>
        public string Domain { get; set; }

        /// <summary>
        /// Gets or sets the server.
        /// </summary>
        /// <value>The server.</value>
        public IWhoisServer Server { get; set; }

        /// <summary>
        /// Gets or sets the date the domain was created.
        /// </summary>
        /// <value>The created.</value>
        public DateTime? Created { get; set; }

        /// <summary>
        /// Gets or sets the registrant.
        /// </summary>
        /// <value>
        /// The registrant.
        /// </value>
        public Contact Registrant { get; set; }

        /// <summary>
        /// Gets or sets the technical contact.
        /// </summary>
        /// <value>
        /// The technical contact.
        /// </value>
        public Contact TechnicalContact { get; set; }

        /// <summary>
        /// Gets or sets the admin contact.
        /// </summary>
        /// <value>
        /// The admin contact.
        /// </value>
        public Contact AdminContact { get; set; }

        public IList<string> Nameservers { get; private set; }

        /// <summary>
        /// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </returns>
        public override string ToString()
        {
            return Text;
        }

        public object Clone()
        {
            var clone = new WhoisRecord(Text);

            return clone;
        }
    }
}