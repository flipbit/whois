using System;

namespace Whois.Parsers
{
    /// <summary>
    /// Converts per WHOIS server domain statuses into a <see cref="WhoisStatus"/>.
    /// </summary>
    public class WhoisStatusParser
    {
        public WhoisStatus Parse(string whoisServer, string status, WhoisStatus existing)
        {
            if (Equals(status, "auto-renew grace")) return WhoisStatus.NotAssigned;
            if (Equals(status, "pending delete")) return WhoisStatus.PendingDelete;
            if (Equals(status, "pendingdelete")) return WhoisStatus.PendingDelete;
            if (Equals(status, "redemption")) return WhoisStatus.Redemption;
            if (Equals(status, "UNCONFIRMED")) return WhoisStatus.Unconfirmed;
            if (Equals(status, "Deactivated")) return WhoisStatus.Deactivated;
            if (Equals(status, "failed")) return WhoisStatus.Failed;
            if (Equals(status, "Reserved")) return WhoisStatus.Reserved;
            if (Equals(status, "inactive")) return WhoisStatus.NotAssigned;
            if (Equals(status, "in quarantine")) return WhoisStatus.Quarantined;
            if (Equals(status, "Grace Period")) return WhoisStatus.Other;
            if (Equals(status, "Grace-Period")) return WhoisStatus.Other;
            if (Equals(status, "Available")) return WhoisStatus.NotFound;
            if (Equals(status, "Transfer Locked")) return WhoisStatus.Locked;
            if (Equals(status, "Deleted")) return WhoisStatus.PendingDelete;
            if (Equals(status, "To be suspended")) return WhoisStatus.Suspended;
            if (Equals(status, "Suspended")) return WhoisStatus.Suspended;
            if (Equals(status, "RedemptionPeriod")) return WhoisStatus.Redemption;
            if (Equals(status, "AutoRenewGracePeriod")) return WhoisStatus.Other;
            if (Equals(status, "Expired")) return WhoisStatus.Expired;
            if (Equals(status, "NOT_OPEN")) return WhoisStatus.Other;
            if (Equals(status, "BLOCKED")) return WhoisStatus.Blocked;
            if (Equals(status, "UNASSIGNABLE")) return WhoisStatus.Unavailable;
            if (Equals(status, "REDEMPTION-NO-PROVIDER")) return WhoisStatus.Redemption;
            if (Equals(status, "pendingUpdate")) return WhoisStatus.Other;
            if (Equals(status, "pendingTransfer")) return WhoisStatus.Other;
            if (Equals(status, "PENDING-DELETE")) return WhoisStatus.PendingDelete;
            if (Equals(status, "NO-PROVIDER")) return WhoisStatus.Other;
            if (Equals(status, "This WHOIS server does not have any records for that zone.")) return WhoisStatus.Invalid;
            if (Equals(status, "Not Registered")) return WhoisStatus.NotFound;
            if (Equals(status, "Renewal required.")) return WhoisStatus.Suspended;
            if (Equals(status, "No registration status listed.")) return WhoisStatus.Reserved;
            if (Equals(status, "Renewal request being processed.")) return WhoisStatus.Other;
            if (Equals(status, "Registration request being processed.")) return WhoisStatus.Other;
            if (Equals(status, "No longer required")) return WhoisStatus.Other;
            if (Equals(status, "SUSPENDIDO")) return WhoisStatus.Suspended;
            if (Equals(status, "Suspended")) return WhoisStatus.Other;
            if (Equals(status, "DOM_WARN")) return WhoisStatus.Other;
            if (Equals(status, "DOM_TA")) return WhoisStatus.Other;
            if (Equals(status, "DOM_LNOT")) return WhoisStatus.Other;
            if (Equals(status, "DOM_HELD")) return WhoisStatus.Other;
            if (Equals(status, "DOM_EXP")) return WhoisStatus.Expired;
            if (Equals(status, "DOM_DAKT")) return WhoisStatus.Other;
            if (Equals(status, "free")) return WhoisStatus.NotFound;
            if (Equals(status, "Prohibited String - Object Cannot Be Registered")) return WhoisStatus.NotAvailable;
            if (Equals(status, "Locked")) return WhoisStatus.Locked;
            if (Equals(status, "In Transfer")) return WhoisStatus.Other;
            if (Equals(status, "500 Invalid characters in query string")) return WhoisStatus.Invalid;
            if (Equals(status, "220 Available")) return WhoisStatus.NotFound;
            if (Equals(status, "210 PendingRelease")) return WhoisStatus.Other;
            if (Equals(status, "440 Request Denied")) return WhoisStatus.Throttled;

            if (whoisServer == "whois.dns.pt")
            {
                if (Equals(status, "TECH-PRO")) return WhoisStatus.Other;
            }

            if (whoisServer == "whois.iis.se")
            {
                if (Equals(status, "system")) return WhoisStatus.NotAssigned;
            }


            return existing;
        }

        private static bool Equals(string status, string value)
        {
            return string.Compare(status, value, StringComparison.InvariantCultureIgnoreCase) == 0;
        }
    }
}
