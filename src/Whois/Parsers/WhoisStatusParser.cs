namespace Whois.Parsers;

/// <summary>
/// Converts per WHOIS server domain statuses into a <see cref="RegistrationStatus"/>.
/// </summary>
public class WhoisStatusParser
{
    public static RegistrationStatus Parse(string whoisServer, string? status, RegistrationStatus existing)
    {
        if (Equals(status, "auto-renew grace")) return RegistrationStatus.NotAssigned;
        if (Equals(status, "pending delete")) return RegistrationStatus.PendingDelete;
        if (Equals(status, "pendingdelete")) return RegistrationStatus.PendingDelete;
        if (Equals(status, "redemption")) return RegistrationStatus.Redemption;
        if (Equals(status, "UNCONFIRMED")) return RegistrationStatus.Unconfirmed;
        if (Equals(status, "Deactivated")) return RegistrationStatus.Deactivated;
        if (Equals(status, "failed")) return RegistrationStatus.Failed;
        if (Equals(status, "Reserved")) return RegistrationStatus.Reserved;
        if (Equals(status, "inactive")) return RegistrationStatus.NotAssigned;
        if (Equals(status, "in quarantine")) return RegistrationStatus.Quarantined;
        if (Equals(status, "Grace Period")) return RegistrationStatus.Other;
        if (Equals(status, "Grace-Period")) return RegistrationStatus.Other;
        if (Equals(status, "Available")) return RegistrationStatus.NotFound;
        if (Equals(status, "Transfer Locked")) return RegistrationStatus.Locked;
        if (Equals(status, "Deleted")) return RegistrationStatus.PendingDelete;
        if (Equals(status, "To be suspended")) return RegistrationStatus.Suspended;
        if (Equals(status, "Suspended")) return RegistrationStatus.Suspended;
        if (Equals(status, "RedemptionPeriod")) return RegistrationStatus.Redemption;
        if (Equals(status, "AutoRenewGracePeriod")) return RegistrationStatus.Other;
        if (Equals(status, "Expired")) return RegistrationStatus.Expired;
        if (Equals(status, "NOT_OPEN")) return RegistrationStatus.Other;
        if (Equals(status, "BLOCKED")) return RegistrationStatus.Blocked;
        if (Equals(status, "UNASSIGNABLE")) return RegistrationStatus.Unavailable;
        if (Equals(status, "REDEMPTION-NO-PROVIDER")) return RegistrationStatus.Redemption;
        if (Equals(status, "pendingUpdate")) return RegistrationStatus.Other;
        if (Equals(status, "pendingTransfer")) return RegistrationStatus.Other;
        if (Equals(status, "PENDING-DELETE")) return RegistrationStatus.PendingDelete;
        if (Equals(status, "NO-PROVIDER")) return RegistrationStatus.Other;
        if (Equals(status, "This WHOIS server does not have any records for that zone.")) return RegistrationStatus.Invalid;
        if (Equals(status, "Not Registered")) return RegistrationStatus.NotFound;
        if (Equals(status, "Renewal required.")) return RegistrationStatus.Suspended;
        if (Equals(status, "No registration status listed.")) return RegistrationStatus.Reserved;
        if (Equals(status, "Renewal request being processed.")) return RegistrationStatus.Other;
        if (Equals(status, "Registration request being processed.")) return RegistrationStatus.Other;
        if (Equals(status, "No longer required")) return RegistrationStatus.Other;
        if (Equals(status, "SUSPENDIDO")) return RegistrationStatus.Suspended;
        if (Equals(status, "DOM_WARN")) return RegistrationStatus.Other;
        if (Equals(status, "DOM_TA")) return RegistrationStatus.Other;
        if (Equals(status, "DOM_LNOT")) return RegistrationStatus.Other;
        if (Equals(status, "DOM_HELD")) return RegistrationStatus.Other;
        if (Equals(status, "DOM_EXP")) return RegistrationStatus.Expired;
        if (Equals(status, "DOM_DAKT")) return RegistrationStatus.Other;
        if (Equals(status, "free")) return RegistrationStatus.NotFound;
        if (Equals(status, "Prohibited String - Object Cannot Be Registered")) return RegistrationStatus.NotAvailable;
        if (Equals(status, "Locked")) return RegistrationStatus.Locked;
        if (Equals(status, "In Transfer")) return RegistrationStatus.Other;
        if (Equals(status, "500 Invalid characters in query string")) return RegistrationStatus.Invalid;
        if (Equals(status, "220 Available")) return RegistrationStatus.NotFound;
        if (Equals(status, "210 PendingRelease")) return RegistrationStatus.Other;
        if (Equals(status, "440 Request Denied")) return RegistrationStatus.Throttled;

        if (string.Equals(whoisServer, "whois.dns.pt", StringComparison.Ordinal))
        {
            if (Equals(status, "TECH-PRO")) return RegistrationStatus.Other;
        }

        if (string.Equals(whoisServer, "whois.iis.se", StringComparison.Ordinal))
        {
            if (Equals(status, "system")) return RegistrationStatus.NotAssigned;
        }


        return existing;
    }

    private static bool Equals(string? status, string value)
    {
        return string.Compare(status, value, StringComparison.OrdinalIgnoreCase) == 0;
    }
}
