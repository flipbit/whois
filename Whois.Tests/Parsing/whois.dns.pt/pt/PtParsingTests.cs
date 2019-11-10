using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Pt.Pt
{
    [TestFixture]
    public class PtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pt/pt/Found", response.TemplateName);

            Assert.AreEqual("google.pt", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2003, 01, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA", response.Registrant.Address[1]);
            Assert.AreEqual("94043 null", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Markmonitor - CCOPS", response.BillingContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Markmonitor - CCOPS", response.TechnicalContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_techpro()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "other_status_techpro.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pt/pt/Found", response.TemplateName);

            Assert.AreEqual("wiki.pt", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 02, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 03, 01, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.Registrant.Name);
            Assert.AreEqual("registrars@ping.pt", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Rua Ricardo Severo, Nº 3 - 5º Dto.", response.Registrant.Address[0]);
            Assert.AreEqual("Porto", response.Registrant.Address[1]);
            Assert.AreEqual("4050-515 Porto", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.BillingContact.Name);
            Assert.AreEqual("registrars@ping.pt", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.TechnicalContact.Name);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("TECH-PRO", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "not_found.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pt/pt/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.pt", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "inactive.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pt/pt/Found", response.TemplateName);

            Assert.AreEqual("wiki.pt", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 02, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 03, 01, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.Registrant.Name);
            Assert.AreEqual("registrars@ping.pt", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Rua Ricardo Severo, Nº 3 - 5º Dto.", response.Registrant.Address[0]);
            Assert.AreEqual("Porto", response.Registrant.Address[1]);
            Assert.AreEqual("4050-515 Porto", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.BillingContact.Name);
            Assert.AreEqual("registrars@ping.pt", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.TechnicalContact.Name);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("TECH-PRO", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pt/pt/Found", response.TemplateName);

            Assert.AreEqual("google.pt", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2003, 01, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA", response.Registrant.Address[1]);
            Assert.AreEqual("94043 null", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Markmonitor - CCOPS", response.BillingContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Markmonitor - CCOPS", response.TechnicalContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(14, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "reserved.txt");
            var response = parser.Parse("whois.dns.pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pt/pt/Found", response.TemplateName);

            Assert.AreEqual("wiki.pt", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 02, 09, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.Registrant.Name);
            Assert.AreEqual("registos@portugalmail.pt", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Rua Ricardo Severo, Nº 3 - 5º Dto.", response.Registrant.Address[0]);
            Assert.AreEqual("4050-515 Porto", response.Registrant.Address[1]);
            Assert.AreEqual("PT", response.Registrant.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.BillingContact.Name);
            Assert.AreEqual("registos@portugalmail.pt", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Portugalmail - Comunicações S.A.", response.TechnicalContact.Name);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("RESERVED", response.DomainStatus[0]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
