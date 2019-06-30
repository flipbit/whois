using System;
using System.Collections.Generic;
using System.Text;
using Whois.Models;

namespace Whois.Parsers
{
    public class WhoisResponseStatusParser
    {
        public WhoisResponseStatus Parse(string whoisServerUrl, string tld, string status, WhoisResponseStatus existing)
        {
            if (whoisServerUrl == "whois.cira.ca")
            {
                if (status == "auto-renew grace")
                {
                    return WhoisResponseStatus.NotAssigned;
                }

                if (status == "pending delete")
                {
                    return WhoisResponseStatus.PendingDelete;
                }

                if (status == "redemption")
                {
                    return WhoisResponseStatus.Redemption;
                }
            }

            if (whoisServerUrl == "whois.co.ug")
            {
                if (status == "UNCONFIRMED")
                {
                    return WhoisResponseStatus.Unconfirmed;
                }
            }

            return existing;
        }
    }
}
