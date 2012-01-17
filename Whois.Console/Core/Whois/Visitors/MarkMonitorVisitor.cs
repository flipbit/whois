using System;
using Flipbit.Core.Whois.Arrays;
using Flipbit.Core.Whois.Domain;
using Flipbit.Core.Whois.Interfaces;
using Flipbit.Core.Whois.Strings;

namespace Flipbit.Core.Whois.Visitors
{
    /// <summary>
    /// Parses Mark Monitor WHOIS data
    /// </summary>
    public class MarkMonitorVisitor : IWhoisVisitor
    {
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