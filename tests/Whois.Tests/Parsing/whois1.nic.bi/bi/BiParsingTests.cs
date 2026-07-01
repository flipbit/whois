using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois1.Nic.Bi.Bi
{
    [TestFixture]
    public class BiParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois1.nic.bi", "bi", "not_found.txt");
            var response = parser.Parse("whois1.nic.bi", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.bi", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois1.nic.bi", "bi", "found.txt");
            var response = parser.Parse("whois1.nic.bi", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.bi", response.DomainName.ToString());
            Assert.AreEqual("2633NIC-BI", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonito", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 12, 05, 07, 16, 04, 538, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 09, 29, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 09, 29, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("85593NIC-BI", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6506234000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("85593NIC-BI", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6506234000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("85594NIC-BI", response.BillingContact.RegistryId);
            Assert.AreEqual("MM Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor Inc", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("Idaho", response.BillingContact.Address[2]);
            Assert.AreEqual("83704", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("85593NIC-BI", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6506234000", response.TechnicalContact.TelephoneNumber);
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
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(53, response.FieldsParsed);
        }
    }
}
