using System;
using System.Text;
using System.Globalization;
using Whois.Domain;
using Whois.Extensions;
using Whois.Interfaces;

namespace Whois.Visitors
{
    /// <summary>
    /// Parses Registro.BR WHOIS data
    /// </summary>
    public class RegistroBrVisitor : IWhoisVisitor
    {
        /// <summary>
        /// Gets the current character encoding that the current WhoisVisitor
        /// object is using.
        /// </summary>
        /// <returns>The current character encoding used by the current visitor.</returns>
        public Encoding CurrentEncoding { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RegistroBrVisitor"/> class.
        /// </summary>
        public RegistroBrVisitor() : this(Encoding.UTF8)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RegistroBrVisitor"/> class.
        /// </summary>
        /// <param name="encoding">The encoding used to read and write strings.</param>
        public RegistroBrVisitor(Encoding encoding)
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
            var referralIndex = record.Text.IndexOfLineContaining("created:     ");

            if (referralIndex > -1)
            {
                var registationString = record.Text.Containing("created:     ", referralIndex);

                registationString = registationString.SubstringAfterChar(":").SubstringBeforeChar("#").Trim();

                DateTime registrationDate;

                if (DateTime.TryParseExact(registationString, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out registrationDate))
                {
                    record.Created = registrationDate;
                }
            }

            return record; //created:
        }
    }
}