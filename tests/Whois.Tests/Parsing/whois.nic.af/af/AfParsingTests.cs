using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Af.Af
{
    [TestFixture]
    public class AfParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.af", "af", "not_found.txt");
            var response = parser.Parse("whois.nic.af", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.af/af/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.af", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.af", "af", "found.txt");
            var response = parser.Parse("whois.nic.af", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.af", response.DomainName.ToString());
            Assert.AreEqual("345679-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.nic.af", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2014, 01, 16, 06, 50, 48, 226, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 10, 05, 03, 51, 17, 979, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 05, 05, 03, 51, 17, 974, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("969675-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
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
            Assert.AreEqual("969675-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.AdminContact.Name);
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
            Assert.AreEqual("969676-CoCCA", response.BillingContact.RegistryId);
            Assert.AreEqual("eMarkmonitor Inc. dba MarkMonitor", response.BillingContact.Name);
            Assert.AreEqual("+1.2083895799", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("PMB 155", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("Idaho 83709", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("969675-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);
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
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(59, response.FieldsParsed);
        }
    }
}
