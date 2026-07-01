using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Ccwhois.Ksregistry.Net.Vg
{
    [TestFixture]
    public class VgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("ccwhois.ksregistry.net", "vg", "not_found.txt");
            var response = parser.Parse("ccwhois.ksregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("ccwhois.ksregistry.net", "vg", "found.txt");
            var response = parser.Parse("ccwhois.ksregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);
            Assert.AreEqual("google.vg", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 3, 1, 0, 2, 14), response.Updated);
            Assert.AreEqual(new DateTime(1999, 6, 5, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2013, 6, 5, 0, 0, 0), response.Expiration);
            Assert.AreEqual("P-GFI26", response.Registrant.RegistryId);
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);
            Assert.AreEqual("Google, Inc.", response.Registrant.Organization);

            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("94043", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);

            Assert.AreEqual("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

            Assert.AreEqual("P-GFI26", response.AdminContact.RegistryId);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Name);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Organization);

            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("94043", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);

            Assert.AreEqual("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

            Assert.AreEqual("P-UDM24", response.BillingContact.RegistryId);
            Assert.AreEqual("UNKNOWN MarkMonitor", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor", response.BillingContact.Organization);

            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("391 North Ancestor Place", response.BillingContact.Address[0]);
            Assert.AreEqual("ID", response.BillingContact.Address[1]);
            Assert.AreEqual("83704", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);

            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895799", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

            Assert.AreEqual("P-GFI26", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google, Inc.", response.TechnicalContact.Name);
            Assert.AreEqual("Google, Inc.", response.TechnicalContact.Organization);

            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+1.6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);
        }
    }
}
