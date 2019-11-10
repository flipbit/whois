using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ly.Ly
{
    [TestFixture]
    public class LyParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ly", "ly", "not_found.txt");
            var response = parser.Parse("whois.nic.ly", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ly/ly/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ly", "ly", "found.txt");
            var response = parser.Parse("whois.nic.ly", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ly/ly/Found", response.TemplateName);


            Assert.AreEqual(new DateTime(2009, 08, 07, 22, 52, 02, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 10, 03, 13, 36, 48, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 10, 03, 13, 36, 48, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+16503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("United States of America", response.Registrant.Address[3]);
            Assert.AreEqual("94043", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+16503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);
            Assert.AreEqual("94043", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895799", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd\\r\\nPMB 155", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("ID", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);
            Assert.AreEqual("83709", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("Domain Admin", response.TechnicalContact.Name);
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895799", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd\\r\\nPMB 155", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise", response.TechnicalContact.Address[1]);
            Assert.AreEqual("ID", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);
            Assert.AreEqual("83709", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com", response.NameServers[1]);
            Assert.AreEqual("ns4.google.com", response.NameServers[2]);
            Assert.AreEqual("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(47, response.FieldsParsed);
        }
    }
}
