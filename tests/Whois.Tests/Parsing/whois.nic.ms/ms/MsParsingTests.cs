using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ms.Ms
{
    [TestFixture]
    public class MsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ms", "ms", "not_found.txt");
            var response = parser.Parse("whois.nic.ms", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ms", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ms", "ms", "found.txt");
            var response = parser.Parse("whois.nic.ms", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.ms", response.DomainName.ToString());
            Assert.AreEqual("23725-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 12, 06, 08, 14, 24, 368, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 06, 04, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 04, 12, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("313268-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("313268-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Name);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("94043", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("313269-CoCCA", response.BillingContact.RegistryId);
            Assert.AreEqual("MarkMonitor", response.BillingContact.Name);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd.", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("ID 83709-1433", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[3]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[4]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(46, response.FieldsParsed);
        }
    }
}
