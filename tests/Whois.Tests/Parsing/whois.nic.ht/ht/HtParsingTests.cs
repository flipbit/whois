using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ht.Ht
{
    [TestFixture]
    public class HtParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ht", "ht", "not_found.txt");
            var response = parser.Parse("whois.nic.ht", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ht", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ht", "ht", "found.txt");
            var response = parser.Parse("whois.nic.ht", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.ht", response.DomainName.ToString());
            Assert.AreEqual("112029-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.nic.ht", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 05, 16, 09, 18, 24, 192, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 06, 17, 23, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 17, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("88185-CoCCA", response.Registrant.RegistryId);
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
            Assert.AreEqual("88185-CoCCA", response.AdminContact.RegistryId);
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
            Assert.AreEqual("182402-CoCCA", response.BillingContact.RegistryId);
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
            Assert.AreEqual("88185-CoCCA", response.TechnicalContact.RegistryId);
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
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[3]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(62, response.FieldsParsed);
        }
    }
}
