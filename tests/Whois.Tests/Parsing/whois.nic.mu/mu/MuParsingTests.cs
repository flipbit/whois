using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mu.Mu
{
    [TestFixture]
    public class MuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.mu", "mu", "not_found.txt");
            var response = parser.Parse("whois.nic.mu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.mu", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.mu", "mu", "found.txt");
            var response = parser.Parse("whois.nic.mu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.mu", response.DomainName.ToString());
            Assert.AreEqual("70557-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 11, 17, 10, 20, 08, 489, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 12, 20, 13, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 12, 19, 13, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("177502-CoCCA", response.Registrant.RegistryId);
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
            Assert.AreEqual("177502-CoCCA", response.AdminContact.RegistryId);
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


             // TechnicalContact Details
            Assert.AreEqual("177502-CoCCA", response.TechnicalContact.RegistryId);
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
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[1]);
            Assert.AreEqual("ok", response.DomainStatus[2]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[3]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(49, response.FieldsParsed);
        }
    }
}
