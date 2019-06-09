using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Vc
{
    [TestFixture]
    public class VcParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.afilias-grs.info", "vc", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", "vc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(1, response.FieldsParsed);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "vc", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", "vc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(49, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.vc", response.DomainName);
            Assert.AreEqual("D133753-LRCC", response.RegistryDomainId);

            Assert.AreEqual("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 2, 17, 17, 43, 40), response.Updated);
            Assert.AreEqual(new DateTime(2005, 6, 29, 0, 58, 18), response.Registered);
            Assert.AreEqual(new DateTime(2011, 6, 29, 0, 58, 18), response.Expiration);
            Assert.AreEqual("mmr-2383", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);

            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Mountain View", response.Registrant.Address[0]);
            Assert.AreEqual("CA", response.Registrant.Address[1]);
            Assert.AreEqual("94043", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);

            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

            Assert.AreEqual("mmr-2383", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);

            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[0]);
            Assert.AreEqual("CA", response.AdminContact.Address[1]);
            Assert.AreEqual("94043", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);

            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

            Assert.AreEqual("mmr-32102", response.BillingContact.RegistryId);
            Assert.AreEqual("domain admin", response.BillingContact.Name);
            Assert.AreEqual("DNStination, Inc.", response.BillingContact.Organization);

            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("San Francisco", response.BillingContact.Address[0]);
            Assert.AreEqual("CA", response.BillingContact.Address[1]);
            Assert.AreEqual("94107", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);

            Assert.AreEqual("+1.4155319335", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("admin@dnstinations.com", response.BillingContact.Email);

            Assert.AreEqual("mmr-2383", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);

            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[0]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);

            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);        }
    }
}
