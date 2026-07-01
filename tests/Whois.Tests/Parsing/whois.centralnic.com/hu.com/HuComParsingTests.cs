using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.HuCom
{
    [TestFixture]
    public class HuComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "hu.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("hotel.hu.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO482594", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Domain Exploitation International", response.Registrar.Name);

             // Registrant Details
            Assert.AreEqual("H1088667", response.Registrant.RegistryId);

             // AdminContact Details
            Assert.AreEqual("H122681", response.AdminContact.RegistryId);

             // BillingContact Details
            Assert.AreEqual("H1088667", response.BillingContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("H122681", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.domain-exploitation.us.com", response.NameServers[0]);
            Assert.AreEqual("ns2.domain-exploitation.us.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(12, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "hu.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "hu.com", "found_status_registered.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("porn.hu.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO970405", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("101Domain, Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.101domain.com", response.Registrar.Url);
            Assert.AreEqual("+1.7604448674", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2014, 2, 11, 0, 16, 13, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 11, 28, 17, 46, 3, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 11, 28, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("RWG000000004273D", response.Registrant.RegistryId);
            Assert.AreEqual("Gintautas Liaskus", response.Registrant.Name);
            Assert.AreEqual("G.Liaskaus firma INFOMEGA", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Kapsu 32-53", response.Registrant.Address[0]);
            Assert.AreEqual("Vilnius", response.Registrant.Address[1]);
            Assert.AreEqual("02167", response.Registrant.Address[2]);
            Assert.AreEqual("LT", response.Registrant.Address[3]);

            Assert.AreEqual("+370.52711457", response.Registrant.TelephoneNumber);
            Assert.AreEqual("infotau@infotau.lt", response.Registrant.Email);

             // AdminContact Details
            Assert.AreEqual("RWG000000004273D", response.AdminContact.RegistryId);
            Assert.AreEqual("Gintautas Liaskus", response.AdminContact.Name);
            Assert.AreEqual("G.Liaskaus firma INFOMEGA", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Kapsu 32-53", response.AdminContact.Address[0]);
            Assert.AreEqual("Vilnius", response.AdminContact.Address[1]);
            Assert.AreEqual("02167", response.AdminContact.Address[2]);
            Assert.AreEqual("LT", response.AdminContact.Address[3]);

            Assert.AreEqual("+370.52711457", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("infotau@infotau.lt", response.AdminContact.Email);

             // BillingContact Details
            Assert.AreEqual("RWG000000004273E", response.BillingContact.RegistryId);
            Assert.AreEqual("Billing Department", response.BillingContact.Name);
            Assert.AreEqual("101Domain, Inc.", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("5858 Edison Pl.", response.BillingContact.Address[0]);
            Assert.AreEqual("Carlsbad", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("92008", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);

            Assert.AreEqual("+1.7604448674", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.7605794996", response.BillingContact.FaxNumber);
            Assert.AreEqual("tech1@101domain.com", response.BillingContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("RWG000000004273D", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Gintautas Liaskus", response.TechnicalContact.Name);
            Assert.AreEqual("G.Liaskaus firma INFOMEGA", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Kapsu 32-53", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Vilnius", response.TechnicalContact.Address[1]);
            Assert.AreEqual("02167", response.TechnicalContact.Address[2]);
            Assert.AreEqual("LT", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+370.52711457", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("infotau@infotau.lt", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.sedoparking.com", response.NameServers[0]);
            Assert.AreEqual("ns2.sedoparking.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("pendingDelete", response.DomainStatus[0]);
            Assert.AreEqual("pendingDelete", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(53, response.FieldsParsed);
        }
    }
}
