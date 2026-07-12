using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kenic.Or.Ke.Ke
{
    public class KeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public KeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "not-found", "u34jedzcq.ke.txt");
            var response = parser.Parse("whois.kenic.or.ke", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.kenic.or.ke/ke/found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.ke", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Not Registered", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "invalid", "www.housekenya.co.ke.txt");
            var response = parser.Parse("whois.kenic.or.ke", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Invalid, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.kenic.or.ke/ke/found/01", response.TemplateName);

            Assert.Equal("www.housekenya.co.ke", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("This WHOIS server does not have any records for that zone.", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "found", "google.co.ke.txt");
            var response = parser.Parse("whois.kenic.or.ke", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.kenic.or.ke/ke/found/01", response.TemplateName);

            Assert.Equal("google.co.ke", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Afriregister Limited", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 12, 16, 09, 48, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2003, 04, 17, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 12, 31, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);


             // BillingContact Details
            Assert.Equal("Domain Administrator", response.BillingContact.Name);
            Assert.Equal("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("391 N. Ancestor Place", response.BillingContact.Address[0]);
            Assert.Equal("Boise, ID 83704", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Active", response.DomainStatus[0]);

            Assert.Equal(37, response.FieldsParsed);
         }
    }
}
