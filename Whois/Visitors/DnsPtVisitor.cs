using System;
using System.Text;
using System.Globalization;
using Whois.Domain;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses DNS.PT WHOIS data
    /// </summary>
    public class DnsPtVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsPtVisitor"/> class.
        /// </summary>
        public DnsPtVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DnsPtVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public DnsPtVisitor(Encoding encoding)
        {
            CurrentEncoding = encoding;
        }

        /// <summary>
        /// Visits the specified record.
        /// </summary>
        /// <param name="record">The record.</param>
        /// <returns></returns>
        public WhoisRecord Visit(WhoisRecord record)
        {
            var referralIndex = record.Text.IndexOfLineContaining("Creation Date (dd/mm/yyyy): ");

            if (referralIndex > -1)
            {
                var registationString = record.Text.Containing("Creation Date (dd/mm/yyyy): ", referralIndex);

                registationString = registationString.SubstringAfterChar(":").Trim();

                DateTime registrationDate;

                if (DateTime.TryParseExact(registationString, "dd/MM/yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out registrationDate))
                {
                    record.Created = registrationDate;
                }
            }

            return record; //created:
        }
    }
}