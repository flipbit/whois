using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ag.Ag
{
    [TestFixture]
    public class AgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ag", "ag", "not_found.txt");
            var response = parser.Parse("whois.nic.ag", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ag", "ag", "found.txt");
            var response = parser.Parse("whois.nic.ag", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.ag", response.DomainName.ToString());
            Assert.AreEqual("D48552-LRCC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 12, 04, 10, 20, 49, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 01, 05, 14, 06, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 01, 05, 14, 06, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("AGRS-129819", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("AGRS-129819", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("AGRS-129293", response.BillingContact.RegistryId);
            Assert.AreEqual("CCOPS", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor", response.BillingContact.Organization);
            Assert.AreEqual("+1.20838957", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.20838957", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("PMB 155", response.BillingContact.Address[0]);
            Assert.AreEqual("10400 Overland Rd.", response.BillingContact.Address[1]);
            Assert.AreEqual("Boise", response.BillingContact.Address[2]);
            Assert.AreEqual("ID", response.BillingContact.Address[3]);
            Assert.AreEqual("83709-1433", response.BillingContact.Address[4]);
            Assert.AreEqual("US", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("AGRS-129819", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);

            Assert.AreEqual(59, response.FieldsParsed);
        }
    }
}
