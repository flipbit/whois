using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Na.Nic.Com.Na.Na
{
    [TestFixture]
    public class NaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.na-nic.com.na", "na", "not_found.txt");
            var response = parser.Parse("whois.na-nic.com.na", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.na", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.na-nic.com.na", "na", "found.txt");
            var response = parser.Parse("whois.na-nic.com.na", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.na", response.DomainName.ToString());
            Assert.AreEqual("4100-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 07, 22, 17, 07, 58, 776, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 03, 27, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 08, 19, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("11969-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc", response.Registrant.Name);
            Assert.AreEqual("info@google.na", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("11898-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("Christina Chiou", response.AdminContact.Name);
            Assert.AreEqual("Google Inc", response.AdminContact.Organization);
            Assert.AreEqual("+1.6503300100", response.AdminContact.TelephoneNumber);
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
            Assert.AreEqual("11871-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("CCOPS Provisioning", response.TechnicalContact.Name);
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Organization);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("10400 Overland Road, PMB 155", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise, ID 83709", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.AreEqual("ok", response.DomainStatus[2]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[3]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[4]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(43, response.FieldsParsed);
        }
    }
}
