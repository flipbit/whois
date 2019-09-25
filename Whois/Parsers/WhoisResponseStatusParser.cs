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
            if (Equals(status, "pendingdelete")) return WhoisResponseStatus.PendingDelete;
            if (Equals(status, "redemption")) return WhoisResponseStatus.Redemption;
            if (Equals(status, "UNCONFIRMED")) return WhoisResponseStatus.Unconfirmed;
            if (Equals(status, "Deactivated")) return WhoisResponseStatus.Deactivated;
            if (Equals(status, "failed")) return WhoisResponseStatus.Failed;
            if (Equals(status, "Reserved")) return WhoisResponseStatus.Reserved;
            if (Equals(status, "inactive")) return WhoisResponseStatus.NotAssigned;
            if (Equals(status, "in quarantine")) return WhoisResponseStatus.Quarantined;
            if (Equals(status, "Grace Period")) return WhoisResponseStatus.Other;
            if (Equals(status, "Grace-Period")) return WhoisResponseStatus.Other;
            if (Equals(status, "Available")) return WhoisResponseStatus.NotFound;
            if (Equals(status, "Transfer Locked")) return WhoisResponseStatus.Locked;
            if (Equals(status, "Deleted")) return WhoisResponseStatus.PendingDelete;
            if (Equals(status, "To be suspended")) return WhoisResponseStatus.Suspended;
            if (Equals(status, "Suspended")) return WhoisResponseStatus.Suspended;
            if (Equals(status, "RedemptionPeriod")) return WhoisResponseStatus.Redemption;
            if (Equals(status, "AutoRenewGracePeriod")) return WhoisResponseStatus.Other;
            if (Equals(status, "Expired")) return WhoisResponseStatus.Expired;
            if (Equals(status, "NOT_OPEN")) return WhoisResponseStatus.Other;
            if (Equals(status, "BLOCKED")) return WhoisResponseStatus.Blocked;
            if (Equals(status, "UNASSIGNABLE")) return WhoisResponseStatus.Unavailable;
            if (Equals(status, "REDEMPTION-NO-PROVIDER")) return WhoisResponseStatus.Redemption;
            if (Equals(status, "pendingUpdate")) return WhoisResponseStatus.Other;
            if (Equals(status, "pendingTransfer")) return WhoisResponseStatus.Other;
            if (Equals(status, "PENDING-DELETE")) return WhoisResponseStatus.PendingDelete;
            if (Equals(status, "NO-PROVIDER")) return WhoisResponseStatus.Other;
            if (Equals(status, "This WHOIS server does not have any records for that zone.")) return WhoisResponseStatus.Invalid;
            if (Equals(status, "Not Registered")) return WhoisResponseStatus.NotFound;
            if (Equals(status, "Renewal required.")) return WhoisResponseStatus.Suspended;
            if (Equals(status, "No registration status listed.")) return WhoisResponseStatus.Reserved;
            if (Equals(status, "Renewal request being processed.")) return WhoisResponseStatus.Other;
            if (Equals(status, "Registration request being processed.")) return WhoisResponseStatus.Other;
            if (Equals(status, "No longer required")) return WhoisResponseStatus.Other;
            if (Equals(status, "SUSPENDIDO")) return WhoisResponseStatus.Suspended;
            if (Equals(status, "Suspended")) return WhoisResponseStatus.Other;
            if (Equals(status, "DOM_WARN")) return WhoisResponseStatus.Other;
            if (Equals(status, "DOM_TA")) return WhoisResponseStatus.Other;
            if (Equals(status, "DOM_LNOT")) return WhoisResponseStatus.Other;
            if (Equals(status, "DOM_HELD")) return WhoisResponseStatus.Other;
            if (Equals(status, "DOM_EXP")) return WhoisResponseStatus.Expired;
            if (Equals(status, "DOM_DAKT")) return WhoisResponseStatus.Other;
            if (Equals(status, "free")) return WhoisResponseStatus.NotFound;
            if (Equals(status, "Prohibited String - Object Cannot Be Registered")) return WhoisResponseStatus.NotAvailable;
            if (Equals(status, "Locked")) return WhoisResponseStatus.Locked;
            if (Equals(status, "In Transfer")) return WhoisResponseStatus.Other;
            if (Equals(status, "500 Invalid characters in query string")) return WhoisResponseStatus.Invalid;
            if (Equals(status, "220 Available")) return WhoisResponseStatus.NotFound;
            if (Equals(status, "210 PendingRelease")) return WhoisResponseStatus.Other;
            if (Equals(status, "440 Request Denied")) return WhoisResponseStatus.Throttled;

            if (whoisServerUrl == "whois.dns.pt")
            {
                if (Equals(status, "TECH-PRO")) return WhoisResponseStatus.Other;
            }

            if (whoisServerUrl == "whois.iis.se")
            {
                if (Equals(status, "system")) return WhoisResponseStatus.NotAssigned;
            }


            return existing;
        }

        private static bool Equals(string status, string value)
        {
            return string.Compare(status, value, StringComparison.InvariantCultureIgnoreCase) == 0;
        }
    }
}
