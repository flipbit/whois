using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cx.Cx
{
    [TestFixture]
    public class CxParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.cx", "cx", "found.txt");
            var response = parser.Parse("whois.nic.cx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("communication.cx", response.DomainName.ToString());
            Assert.AreEqual("919354-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Marcaria.com", response.Registrar.Name);
            Assert.AreEqual("whois.nic.cx", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2013, 07, 17, 10, 26, 59, 132, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 07, 17, 10, 26, 59, 365, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("919353-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("Matthew Marks", response.Registrant.Name);
            Assert.AreEqual("+1.3054348621", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domains@marcaria.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("162 Locarna Way", response.Registrant.Address[0]);
            Assert.AreEqual("Pittsburgh", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("99834-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("Francisco Fuentealba", response.AdminContact.Name);
            Assert.AreEqual("domains@marcaria.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("UNKNOWN", response.AdminContact.Address[0]);
            Assert.AreEqual("Miami", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("99834-CoCCA", response.BillingContact.RegistryId);
            Assert.AreEqual("Francisco Fuentealba", response.BillingContact.Name);
            Assert.AreEqual("domains@marcaria.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("UNKNOWN", response.BillingContact.Address[0]);
            Assert.AreEqual("Miami", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("99834-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Francisco Fuentealba", response.TechnicalContact.Name);
            Assert.AreEqual("domains@marcaria.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("UNKNOWN", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Miami", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns01.trademarkarea.com", response.NameServers[0]);
            Assert.AreEqual("ns02.trademarkarea.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.cx", "cx", "not_found.txt");
            var response = parser.Parse("whois.nic.cx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.cx", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.cx", "cx", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.cx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.cx", response.DomainName.ToString());
            Assert.AreEqual("447518-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("whois.nic.cx", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2014, 06, 28, 09, 18, 02, 516, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 07, 29, 18, 15, 42, 056, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 07, 29, 18, 15, 42, 158, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("969680-CoCCA", response.Registrant.RegistryId);
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
            Assert.AreEqual("969680-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
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
            Assert.AreEqual("969680-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
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
            Assert.AreEqual("ns3.google.com", response.NameServers[1]);
            Assert.AreEqual("ns4.google.com", response.NameServers[2]);
            Assert.AreEqual("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("ok", response.DomainStatus[2]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[3]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(50, response.FieldsParsed);
        }
    }
}
