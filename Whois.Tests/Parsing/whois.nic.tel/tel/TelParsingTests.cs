using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tel.Tel
{
    [TestFixture]
    public class TelParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.tel", "tel", "not_found.txt");
            var response = parser.Parse("whois.nic.tel", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tel/tel/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.tel", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.tel", "tel", "found.txt");
            var response = parser.Parse("whois.nic.tel", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.tel/tel/Found", response.TemplateName);

            Assert.AreEqual("google.tel", response.DomainName.ToString());
            Assert.AreEqual("D587349-TEL", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("292", response.Registrar.IanaId);
            Assert.AreEqual("www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2014, 03, 22, 23, 59, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 03, 23, 23, 59, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 02, 19, 10, 23, 33, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MMR-2383", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);
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
            Assert.AreEqual("MMR-2383", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
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
            Assert.AreEqual("MMR-132163", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Admin", response.BillingContact.Name);
            Assert.AreEqual("DNStination Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.4155319335", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.4155319336", response.BillingContact.FaxNumber);
            Assert.AreEqual("admin@dnstinations.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(7, response.BillingContact.Address.Count);
            Assert.AreEqual("303 Second Street", response.BillingContact.Address[0]);
            Assert.AreEqual("Suite 800 North", response.BillingContact.Address[1]);
            Assert.AreEqual("San Francisco", response.BillingContact.Address[2]);
            Assert.AreEqual("CA", response.BillingContact.Address[3]);
            Assert.AreEqual("94107", response.BillingContact.Address[4]);
            Assert.AreEqual("United States", response.BillingContact.Address[5]);
            Assert.AreEqual("US", response.BillingContact.Address[6]);


             // TechnicalContact Details
            Assert.AreEqual("MMR-2383", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
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
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("a0.cth.dns.nic.tel", response.NameServers[0]);
            Assert.AreEqual("d0.cth.dns.nic.tel", response.NameServers[1]);
            Assert.AreEqual("n0.cth.dns.nic.tel", response.NameServers[2]);
            Assert.AreEqual("s0.cth.dns.nic.tel", response.NameServers[3]);
            Assert.AreEqual("t0.cth.dns.nic.tel", response.NameServers[4]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.AreEqual(65, response.FieldsParsed);
        }
    }
}
