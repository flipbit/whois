using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Us.Us
{
    [TestFixture]
    public class UsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.us", "us", "not_found.txt");
            var response = parser.Parse("whois.nic.us", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.us/us/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.us", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.us", "us", "found.txt");
            var response = parser.Parse("whois.nic.us", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.us/us/Found", response.TemplateName);

            Assert.AreEqual("google.us", response.DomainName.ToString());
            Assert.AreEqual("D775573-US", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("292", response.Registrar.IanaId);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2014, 04, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 04, 19, 23, 15, 57, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 03, 17, 09, 44, 30, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MMR-135878", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);
            Assert.AreEqual("US", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("MMR-136042", response.AdminContact.RegistryId);
            Assert.AreEqual("Christina Chiou", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("United States", response.AdminContact.Address[4]);
            Assert.AreEqual("US", response.AdminContact.Address[5]);


             // BillingContact Details
            Assert.AreEqual("MMR-136042", response.BillingContact.RegistryId);
            Assert.AreEqual("Christina Chiou", response.BillingContact.Name);
            Assert.AreEqual("Google Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.6502530000", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.BillingContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.BillingContact.Address[0]);
            Assert.AreEqual("Mountain View", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("94043", response.BillingContact.Address[3]);
            Assert.AreEqual("United States", response.BillingContact.Address[4]);
            Assert.AreEqual("US", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("MMR-136042", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Christina Chiou", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[4]);
            Assert.AreEqual("US", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.AreEqual(63, response.FieldsParsed);
        }
    }
}
