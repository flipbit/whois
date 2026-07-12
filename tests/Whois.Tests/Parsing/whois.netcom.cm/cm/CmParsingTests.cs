using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Netcom.Cm.Cm
{
    public class CmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CmParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "not-found", "u34jedzcq.cm.txt");
            var response = parser.Parse("whois.netcom.cm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.netcom.cm/cm/found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.cm", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Not Registered", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "found", "google.cm.txt");
            var response = parser.Parse("whois.netcom.cm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.netcom.cm/cm/found/01", response.TemplateName);

            Assert.Equal("google.cm", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 09, 20, 16, 47, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2009, 10, 07, 09, 02, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 10, 07, 09, 02, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("MarkMonitor Inc.", response.BillingContact.Name);
            Assert.Equal("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("391 N Ancestor Place", response.BillingContact.Address[0]);
            Assert.Equal("Boise, ID 83704", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.TechnicalContact.Address[0]);
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

            Assert.Equal(34, response.FieldsParsed);
        }

        [Fact]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "suspended", "suspended.txt");
            var response = parser.Parse("whois.netcom.cm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Suspended, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.netcom.cm/cm/found/01", response.TemplateName);

            Assert.Equal("imdb.cm", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Registrar ANTIC", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 01, 24, 08, 17, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2009, 08, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 08, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("cm.legacy@netcom.cm", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("Camtel | ANTIC l Legacy-Escrow", response.AdminContact.Name);
            Assert.Equal("cm.legacy@netcom.cm", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("Camtel | ANTIC l Legacy-Escrow", response.BillingContact.Name);
            Assert.Equal("cm.legacy@netcom.cm", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("Camtel | ANTIC l Legacy-Escrow", response.TechnicalContact.Name);
            Assert.Equal("cm.legacy@netcom.cm", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.refinedhosting.net", response.NameServers[0]);
            Assert.Equal("ns2.refinedhosting.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Suspended", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }
    }
}
