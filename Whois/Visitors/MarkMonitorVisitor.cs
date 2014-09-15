using System;
using System.Text;
using Whois.Domain;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses Mark Monitor WHOIS data
    /// </summary>
    public class MarkMonitorVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="MarkMonitorVisitor"/> class.
        /// </summary>
        public MarkMonitorVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="MarkMonitorVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public MarkMonitorVisitor(Encoding encoding)
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
            var referralIndex = record.Text.IndexOfLineContaining("Created on");

            if (referralIndex > -1)
            {
                var registationString = record.Text.Containing("Created on", referralIndex);

                registationString = registationString.SubstringAfterChar(":").Trim();

                DateTime registrationDate;

                if (DateTime.TryParse(registationString, out registrationDate))
                {
                    record.Created = registrationDate;
                }
            }

            return record;
        }
    }
}