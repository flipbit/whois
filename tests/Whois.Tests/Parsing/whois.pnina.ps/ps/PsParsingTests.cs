using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Pnina.Ps.Ps
{
    [TestFixture]
    public class PsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.pnina.ps", "ps", "not_found.txt");
            var response = parser.Parse("whois.pnina.ps", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ps", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.pnina.ps", "ps", "found.txt");
            var response = parser.Parse("whois.pnina.ps", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.ps", response.DomainName.ToString());
            Assert.AreEqual("21665-PS", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("+1-208-389-5740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2004, 05, 18, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 05, 18, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("21544-PS", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("001-6-503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("001-6-506188571", response.Registrant.FaxNumber);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy Mountain View- CA- US 94043", response.Registrant.Address[0]);
            Assert.AreEqual("CA", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("21466-PS", response.AdminContact.RegistryId);
            Assert.AreEqual("markmonitor-Inc", response.AdminContact.Name);
            Assert.AreEqual("001-2-083895740", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("001-2-083895771", response.AdminContact.FaxNumber);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd- PMB 155- Boise-ID-US 83709-1433", response.AdminContact.Address[0]);
            Assert.AreEqual("Boise", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("21544-PS", response.BillingContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.BillingContact.Name);
            Assert.AreEqual("001-6-503300100", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("001-6-506188571", response.BillingContact.FaxNumber);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy Mountain View- CA- US 94043", response.BillingContact.Address[0]);
            Assert.AreEqual("CA", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("21466-PS", response.TechnicalContact.RegistryId);
            Assert.AreEqual("markmonitor-Inc", response.TechnicalContact.Name);
            Assert.AreEqual("001-2-083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("001-2-083895771", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd- PMB 155- Boise-ID-US 83709-1433", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.AreEqual("ok", response.DomainStatus[2]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[3]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[4]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(44, response.FieldsParsed);
        }
    }
}
