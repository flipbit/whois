using System;
using System.Text;
using Whois.Domain;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses Nominet UK WHOIS data
    /// </summary>
    public class NominetVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="NominetVisitor"/> class.
        /// </summary>
        public NominetVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NominetVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public NominetVisitor(Encoding encoding)
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
            var referralIndex = record.Text.IndexOfLineContaining("Registered on: ");

            if (referralIndex > -1)
            {
                var registationString = record.Text.Containing("Registered on: ", referralIndex);

                registationString = registationString.SubstringAfterChar(":").Trim();

                registationString = registationString.Replace("before ", "01-");

                DateTime registrationDate;

                if (DateTime.TryParse(registationString, out registrationDate))
                {
                    record.Created = registrationDate;
                }
            }

            return record; //created:
        }
    }
}