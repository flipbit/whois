using System;
using Flipbit.Core.Whois.Arrays;
using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;
using Flipbit.Core.Whois.Strings;

namespace Flipbit.Core.Whois.Visitors
{
    /// <summary>
    /// Parses Nominet UK WHOIS data
    /// </summary>
    public class NominetVisitor : IWhoisVisitor
    {
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