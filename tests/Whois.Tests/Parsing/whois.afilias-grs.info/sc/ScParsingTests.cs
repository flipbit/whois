using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Sc
{
    [TestFixture]
    public class ScParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.afilias-grs.info", "sc", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(1, response.FieldsParsed);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "sc", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.sc", response.DomainName.ToString());
            Assert.AreEqual("D47234-LRCC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 01, 02, 10, 20, 29, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 02, 03, 19, 19, 12, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 02, 03, 19, 19, 12, 000, DateTimeKind.Utc), response.Expiration);

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
            Assert.AreEqual("AGRS-129293", response.AdminContact.RegistryId);
            Assert.AreEqual("CCOPS", response.AdminContact.Name);
            Assert.AreEqual("MarkMonitor", response.AdminContact.Organization);
            Assert.AreEqual("+1.20838957", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.20838957", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("PMB 155", response.AdminContact.Address[0]);
            Assert.AreEqual("10400 Overland Rd.", response.AdminContact.Address[1]);
            Assert.AreEqual("Boise", response.AdminContact.Address[2]);
            Assert.AreEqual("ID", response.AdminContact.Address[3]);
            Assert.AreEqual("83709-1433", response.AdminContact.Address[4]);
            Assert.AreEqual("US", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("mmr-33293", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Admin", response.TechnicalContact.Name);
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("391 N. Ancestor Place", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Suite 150", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Boise", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[3]);
            Assert.AreEqual("83704", response.TechnicalContact.Address[4]);
            Assert.AreEqual("US", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("RENEWPERIOD", response.DomainStatus[3]);

            Assert.AreEqual(48, response.FieldsParsed);
        }
    }
}
