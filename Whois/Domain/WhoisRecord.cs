using System;
using System.Collections;
using System.Collections.Generic;
using System.Net.Mime;
using Whois.Extensions;

namespace Whois.Domain
{
    /// <summary>
    /// Represents WHOIS information for a domain.
    /// </summary>
    public class WhoisRecord : ICloneable
    {
        private string text;

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisRecord"/> class.
        /// </summary>
        public WhoisRecord()
        {
            Text = new ArrayList();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisRecord"/> class.
        /// </summary>
        /// <param name="text">The text.</param>
        public WhoisRecord(string text)
        {
            this.text = text;

            Text = new ArrayList();

            Text.AddRange(text.Split('\n'));
        }

        public IEnumerable<string> AsStrings
        {
            get { return text.Split('\n'); }
        }

        /// <summary>
        /// Gets or sets the text.
        /// </summary>
        /// <value>The text.</value>
        public ArrayList Text { get; set; }

        /// <summary>
        /// Gets or sets the domain.
        /// </summary>
        /// <value>The domain.</value>
        public string Domain { get; set; }

        /// <summary>
        /// Gets or sets the server.
        /// </summary>
        /// <value>The server.</value>
        public string Server { get; set; }

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

        /// <summary>
        /// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.String"/> that represents the current <see cref="T:System.Object"/>.
        /// </returns>
        public override string ToString()
        {
            return Text.AsString();
        }

        public object Clone()
        {
            var clone = new WhoisRecord(text);



            return clone;
        }
    }
}