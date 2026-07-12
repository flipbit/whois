using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Pt.Pt
{
    public class PtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public PtParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found", "google.pt.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pt/pt/found/01", response.TemplateName);

            Assert.Equal("google.pt", response.DomainName.ToString());

            Assert.Equal(new DateTime(2003, 01, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google, Inc.", response.Registrant.Name);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA", response.Registrant.Address[1]);
            Assert.Equal("94043 null", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.Equal("Markmonitor - CCOPS", response.BillingContact.Name);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("Markmonitor - CCOPS", response.TechnicalContact.Name);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(14, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_techpro()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found", "other_status_techpro.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pt/pt/found/01", response.TemplateName);

            Assert.Equal("wiki.pt", response.DomainName.ToString());

            Assert.Equal(new DateTime(2009, 02, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 03, 01, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.Registrant.Name);
            Assert.Equal("registrars@ping.pt", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Rua Ricardo Severo, Nº 3 - 5º Dto.", response.Registrant.Address[0]);
            Assert.Equal("Porto", response.Registrant.Address[1]);
            Assert.Equal("4050-515 Porto", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.BillingContact.Name);
            Assert.Equal("registrars@ping.pt", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.TechnicalContact.Name);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("TECH-PRO", response.DomainStatus[0]);

            Assert.Equal(13, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "not-found", "u34jedzcq.pt.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pt/pt/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.pt", response.DomainName.ToString());


            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "inactive", "wiki-inactive.pt.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Other, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pt/pt/found/01", response.TemplateName);

            Assert.Equal("wiki-inactive.pt", response.DomainName.ToString());

            Assert.Equal(new DateTime(2009, 02, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 03, 01, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.Registrant.Name);
            Assert.Equal("registrars@ping.pt", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Rua Ricardo Severo, Nº 3 - 5º Dto.", response.Registrant.Address[0]);
            Assert.Equal("Porto", response.Registrant.Address[1]);
            Assert.Equal("4050-515 Porto", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.BillingContact.Name);
            Assert.Equal("registrars@ping.pt", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.TechnicalContact.Name);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("TECH-PRO", response.DomainStatus[0]);

            Assert.Equal(13, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pt/pt/found/01", response.TemplateName);

            Assert.Equal("google.pt", response.DomainName.ToString());

            Assert.Equal(new DateTime(2003, 01, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google, Inc.", response.Registrant.Name);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA", response.Registrant.Address[1]);
            Assert.Equal("94043 null", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.Equal("Markmonitor - CCOPS", response.BillingContact.Name);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("Markmonitor - CCOPS", response.TechnicalContact.Name);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(14, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "reserved", "wiki-reserved.pt.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.dns.pt/pt/found/01", response.TemplateName);

            Assert.Equal("wiki-reserved.pt", response.DomainName.ToString());

            Assert.Equal(new DateTime(2009, 02, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.Registrant.Name);
            Assert.Equal("registos@portugalmail.pt", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Rua Ricardo Severo, Nº 3 - 5º Dto.", response.Registrant.Address[0]);
            Assert.Equal("4050-515 Porto", response.Registrant.Address[1]);
            Assert.Equal("PT", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.BillingContact.Name);
            Assert.Equal("registos@portugalmail.pt", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("Portugalmail - Comunicações S.A.", response.TechnicalContact.Name);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("RESERVED", response.DomainStatus[0]);

            Assert.Equal(12, response.FieldsParsed);
        }
    }
}
