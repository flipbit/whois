using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gd.Gd
{
    [TestFixture]
    public class GdParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.gd", "gd", "not_found.txt");
            var response = parser.Parse("whois.nic.gd", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.gd/gd/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.gd", "gd", "found.txt");
            var response = parser.Parse("whois.nic.gd", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.gd/gd/Found", response.TemplateName);

            Assert.AreEqual("google.gd", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 11, 12, 16, 07, 05, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 12, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 12, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("P-GXI35", response.Registrant.RegistryId);
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);
            Assert.AreEqual("Google, Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("94043", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("P-GXI35", response.AdminContact.RegistryId);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Name);
            Assert.AreEqual("Google, Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6506181499", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("94043", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("UNKNOWN MarkMonitor", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("10400 Overland Road", response.BillingContact.Address[0]);
            Assert.AreEqual("Idaho", response.BillingContact.Address[1]);
            Assert.AreEqual("83709", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("P-GXI35", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google, Inc.", response.TechnicalContact.Name);
            Assert.AreEqual("Google, Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6506181499", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientupdateprohibited", response.DomainStatus[0]);
            Assert.AreEqual("clienttransferprohibited", response.DomainStatus[1]);

            Assert.AreEqual(50, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.gd", "gd", "reserved.txt");
            var response = parser.Parse("whois.nic.gd", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.gd/gd/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }
    }
}
