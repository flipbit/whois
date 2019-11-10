using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Pw.Pw
{
    [TestFixture]
    public class PwParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.pw", "pw", "not_found.txt");
            var response = parser.Parse("whois.nic.pw", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.pw", "pw", "found.txt");
            var response = parser.Parse("whois.nic.pw", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.pw", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO949924", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("292", response.Registrar.IanaId);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2014, 01, 18, 00, 13, 36, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 10, 12, 10, 19, 46, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 02, 10, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H2396041", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin - Google Inc", response.Registrant.Name);
            Assert.AreEqual("Google Inc", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("H2396041", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin - Google Inc", response.AdminContact.Name);
            Assert.AreEqual("Google Inc", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("7061-EM", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor, Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("Emerald Tech Center", response.BillingContact.Address[0]);
            Assert.AreEqual("391 N. Ancestor Place", response.BillingContact.Address[1]);
            Assert.AreEqual("Boise", response.BillingContact.Address[2]);
            Assert.AreEqual("ID", response.BillingContact.Address[3]);
            Assert.AreEqual("83704", response.BillingContact.Address[4]);
            Assert.AreEqual("US", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("H2396041", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin - Google Inc", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(7, response.NameServers.Count);
            Assert.AreEqual("ns1.markmonitor.com", response.NameServers[0]);
            Assert.AreEqual("ns2.markmonitor.com", response.NameServers[1]);
            Assert.AreEqual("ns3.markmonitor.com", response.NameServers[2]);
            Assert.AreEqual("ns4.markmonitor.com", response.NameServers[3]);
            Assert.AreEqual("ns5.markmonitor.com", response.NameServers[4]);
            Assert.AreEqual("ns6.markmonitor.com", response.NameServers[5]);
            Assert.AreEqual("ns7.markmonitor.com", response.NameServers[6]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[2]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[3]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(65, response.FieldsParsed);
        }
    }
}
