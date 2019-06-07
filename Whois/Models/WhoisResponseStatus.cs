using System;
using System.Collections.Generic;
using System.Text;

namespace Whois.Models
{
    public enum WhoisResponseStatus
    {
        Unknown,
        Found, 
        NotFound, 
        Error, 
        Throttled,
        Expired,
        PendingDelete,
        Reserved,
        Suspended,
        NotAssigned,
        Invalid,
        Inactive,
        Locked,
        Quarantined,
        OutOfService,
        NotAvailable,
        Deactivated,
        Failed,
        Unconfirmed,
        Unavailable,
        ToBeReleased,
        Redemption,
        Blocked,
        Other
    }
}
