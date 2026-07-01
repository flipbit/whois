using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Coza.Whois.Registry.Net.Za.CoZa
{
    [TestFixture]
    public class CoZaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found.txt");
            var response = parser.Parse("coza-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual("fnb.co.za", response.DomainName.ToString());
            Assert.AreEqual("dom_1ZW3S--1", response.RegistryDomainId);

            Assert.AreEqual("Lexsynergy Limited", response.Registrar.Name);
            Assert.AreEqual("coza-whois12.dns.net.za", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2016, 12, 1, 23, 41, 21, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1994, 12, 31, 22, 0, 0, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 12, 31, 22, 0, 0, DateTimeKind.Utc), response.Expiration);
            Assert.AreEqual("FirstRand Bank Limited", response.Registrant.Name);
            Assert.AreEqual("FirstRand Bank Limited", response.Registrant.Organization);

            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.Registrant.Address[0]);
            Assert.AreEqual("Sandton", response.Registrant.Address[1]);
            Assert.AreEqual("Gauteng", response.Registrant.Address[2]);
            Assert.AreEqual("2196", response.Registrant.Address[3]);
            Assert.AreEqual("ZA", response.Registrant.Address[4]);

            Assert.AreEqual("+27.112828000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domreg.admins@firstrand.co.za", response.Registrant.Email);

            Assert.AreEqual("LEX-1EU-1Y58", response.AdminContact.RegistryId);
            Assert.AreEqual("FirstRand Bank Limited", response.AdminContact.Name);
            Assert.AreEqual("FirstRand Bank Limited", response.AdminContact.Organization);

            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.AdminContact.Address[0]);
            Assert.AreEqual("Sandton", response.AdminContact.Address[1]);
            Assert.AreEqual("Gauteng", response.AdminContact.Address[2]);
            Assert.AreEqual("2196", response.AdminContact.Address[3]);
            Assert.AreEqual("ZA", response.AdminContact.Address[4]);

            Assert.AreEqual("+27.112828000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domreg.admins@firstrand.co.za", response.AdminContact.Email);

            Assert.AreEqual("LEX-1EU-1Y58", response.BillingContact.RegistryId);
            Assert.AreEqual("FirstRand Bank Limited", response.BillingContact.Name);
            Assert.AreEqual("FirstRand Bank Limited", response.BillingContact.Organization);

            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.BillingContact.Address[0]);
            Assert.AreEqual("Sandton", response.BillingContact.Address[1]);
            Assert.AreEqual("Gauteng", response.BillingContact.Address[2]);
            Assert.AreEqual("2196", response.BillingContact.Address[3]);
            Assert.AreEqual("ZA", response.BillingContact.Address[4]);

            Assert.AreEqual("+27.112828000", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("domreg.admins@firstrand.co.za", response.BillingContact.Email);

            Assert.AreEqual("LEX-1EU-1Y58", response.TechnicalContact.RegistryId);
            Assert.AreEqual("FirstRand Bank Limited", response.TechnicalContact.Name);
            Assert.AreEqual("FirstRand Bank Limited", response.TechnicalContact.Organization);

            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Sandton", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Gauteng", response.TechnicalContact.Address[2]);
            Assert.AreEqual("2196", response.TechnicalContact.Address[3]);
            Assert.AreEqual("ZA", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+27.112828000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domreg.admins@firstrand.co.za", response.TechnicalContact.Email);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns01.fnbconnect.co.za", response.NameServers[0]);
            Assert.AreEqual("ns02.fnbconnect.co.za", response.NameServers[1]);
            Assert.AreEqual("ns03.fnbconnect.co.za", response.NameServers[2]);
            Assert.AreEqual("ns04.fnbconnect.co.za", response.NameServers[3]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "throttled.txt");
            var response = parser.Parse("coza-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "not_found.txt");
            var response = parser.Parse("coza-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual("nosuchdomainregistered.co.za", response.DomainName.ToString());
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found_status_registered.txt");
            var response = parser.Parse("coza-whois.registry.net.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual("google.co.za", response.DomainName.ToString());
            Assert.AreEqual("dom_1SZMF--1", response.RegistryDomainId);

            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("coza-whois12.dns.net.za", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2016, 9, 24, 16, 20, 9, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 6, 25, 20, 37, 59, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 6, 25, 20, 37, 59, DateTimeKind.Utc), response.Expiration);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);

            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

            Assert.AreEqual("mmr-2383", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.AdminContact.Name);

            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);

            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

            Assert.AreEqual("mmr-2383", response.BillingContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.BillingContact.Name);

            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.BillingContact.Address[0]);
            Assert.AreEqual("Mountain View", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("94043", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);

            Assert.AreEqual("+1.6502530000", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.BillingContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.BillingContact.Email);

            Assert.AreEqual("mmr-2383", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);

            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
        }
    }
}
