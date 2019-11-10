using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mg.Mg
{
    [TestFixture]
    public class MgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.mg", "mg", "not_found.txt");
            var response = parser.Parse("whois.nic.mg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.mg", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.mg", "mg", "found.txt");
            var response = parser.Parse("whois.nic.mg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.mg", response.DomainName.ToString());
            Assert.AreEqual("1915-nicmg", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 10, 29, 15, 13, 49, 869, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 06, 18, 08, 38, 20, 671, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 11, 26, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("4112-nicmg", response.Registrant.RegistryId);
            Assert.AreEqual("GOOGLE INC", response.Registrant.Name);
            Assert.AreEqual("GOOGLE INC", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Street Migrate", response.Registrant.Address[0]);
            Assert.AreEqual("Antananarivo", response.Registrant.Address[1]);
            Assert.AreEqual("Antananarivo", response.Registrant.Address[2]);
            Assert.AreEqual("101", response.Registrant.Address[3]);
            Assert.AreEqual("MG", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("4113-nicmg", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Rafaralahisoa Emmanuel", response.TechnicalContact.Name);
            Assert.AreEqual("DTS", response.TechnicalContact.Organization);
            Assert.AreEqual("+261.202220359", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+261.202220360", response.TechnicalContact.FaxNumber);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Immeuble Galaxy", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Antananarivo", response.TechnicalContact.Address[1]);
            Assert.AreEqual("101", response.TechnicalContact.Address[2]);
            Assert.AreEqual("MG", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[3]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[4]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(38, response.FieldsParsed);
        }
    }
}
