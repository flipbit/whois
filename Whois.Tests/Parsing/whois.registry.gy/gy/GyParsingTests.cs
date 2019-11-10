using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Gy.Gy
{
    [TestFixture]
    public class GyParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registry.gy", "gy", "not_found.txt");
            var response = parser.Parse("whois.registry.gy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.gy", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.gy", "gy", "found.txt");
            var response = parser.Parse("whois.registry.gy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.gy", response.DomainName.ToString());
            Assert.AreEqual("573328-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.registry.gy", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2014, 01, 16, 06, 53, 13, 620, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 05, 12, 17, 56, 23, 090, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 04, 23, 30, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("969683-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("google Inc", response.Registrant.Name);
            Assert.AreEqual("+1.6506188571", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("mountain View", response.Registrant.Address[0]);
            Assert.AreEqual("Unknown", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("969684-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("+1.6506188571", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("USA", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("969686-CoCCA", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("969685-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Unknown", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Unknown", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Unknown", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[0]);
            Assert.AreEqual("ok", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[3]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[4]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(44, response.FieldsParsed);
        }
    }
}
