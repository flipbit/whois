using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fm.Fm
{
    [TestFixture]
    public class FmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            LogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fm", "fm", "not_found.txt");
            var response = parser.Parse("whois.nic.fm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fm", "fm", "found.txt");
            var response = parser.Parse("whois.nic.fm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.fm", response.DomainName.ToString());
            Assert.AreEqual("D34865469-CNIC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor, Inc.", response.Registrar.Name);
            Assert.AreEqual("292", response.Registrar.IanaId);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2017, 10, 20, 17, 48, 39, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 09, 05, 23, 59, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 09, 04, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("C78398194-CNIC", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google, Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@GOOGLE.COM", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("C78398194-CNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@GOOGLE.COM", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("C78382669-CNIC", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Billing", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor, Inc", response.BillingContact.Organization);
            Assert.AreEqual("+1..208389574", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1..20838958", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd, PMB 155", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("ID", response.BillingContact.Address[2]);
            Assert.AreEqual("83709", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("C78398194-CNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google, Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@GOOGLE.COM", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns3.google.com", response.NameServers[1]);
            Assert.AreEqual("ns2.google.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[1]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(61, response.FieldsParsed);
        }
    }
}
