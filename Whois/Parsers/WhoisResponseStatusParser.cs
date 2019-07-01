using System;
using Whois.Models;

namespace Whois.Parsers
{
    /// <summary>
    /// Converts per WHOIS server domain statuses into a <see cref="WhoisResponseStatus"/>.
    /// </summary>
    public class WhoisResponseStatusParser
    {
        public WhoisResponseStatus Parse(string whoisServerUrl, string tld, string status, WhoisResponseStatus existing)
        {
            if (Equals(status, "auto-renew grace")) return WhoisResponseStatus.NotAssigned;
            if (Equals(status, "pending delete")) return WhoisResponseStatus.PendingDelete;
            if (Equals(status, "redemption")) return WhoisResponseStatus.Redemption;
            if (Equals(status, "UNCONFIRMED")) return WhoisResponseStatus.Unconfirmed;
            if (Equals(status, "Deactivated")) return WhoisResponseStatus.Deactivated;
            if (Equals(status, "failed")) return WhoisResponseStatus.Failed;
            if (Equals(status, "Reserved")) return WhoisResponseStatus.Reserved;

            if (whoisServerUrl == "whois.dns.pt")
            {
                if (Equals(status, "TECH-PRO")) return WhoisResponseStatus.Other;
            }


            return existing;
        }

        private static bool Equals(string status, string value)
        {
            return string.Compare(status, value, StringComparison.InvariantCultureIgnoreCase) == 0;
        }
    }
}
