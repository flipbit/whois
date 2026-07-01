using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Uniregistry.Net.Tattoo
{
    [TestFixture]
    public class TattooParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "not_found.txt");
            var response = parser.Parse("whois.uniregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.uniregistry.net/tattoo/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.tattoo", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "found.txt");
            var response = parser.Parse("whois.uniregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.tattoo", response.DomainName.ToString());
            Assert.AreEqual("DO_4810ec9890fdf872f2e23b58df485dc4-ISC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Uniregistry, Corp.", response.Registrar.Name);
            Assert.AreEqual("9999", response.Registrar.IanaId);
            Assert.AreEqual("http://whois.uniregistry.net", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 11, 09, 02, 51, 24, 230, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 09, 16, 14, 21, 26, 648, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2023, 09, 16, 14, 21, 26, 648, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("uniregistry", response.Registrant.RegistryId);
            Assert.AreEqual("Uniregistry Registry Internal Resources", response.Registrant.Name);
            Assert.AreEqual("Uniregistry, Corp", response.Registrant.Organization);
            Assert.AreEqual("+1.3457496263", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.3457496263", response.Registrant.FaxNumber);
            Assert.AreEqual("info+whois@uniregistry.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("PO Box 1361", response.Registrant.Address[0]);
            Assert.AreEqual("Grand Cayman", response.Registrant.Address[1]);
            Assert.AreEqual("George Town", response.Registrant.Address[2]);
            Assert.AreEqual("KY1-1108", response.Registrant.Address[3]);
            Assert.AreEqual("KY", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("tattoo-admin", response.AdminContact.RegistryId);
            Assert.AreEqual("Uniregistry admin contact", response.AdminContact.Name);
            Assert.AreEqual("Uniregistry, Corp", response.AdminContact.Organization);
            Assert.AreEqual("+1.3457496263", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.3457496263", response.AdminContact.FaxNumber);
            Assert.AreEqual("admin@nic.tattoo", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("PO Box 1361", response.AdminContact.Address[0]);
            Assert.AreEqual("Grand Cayman", response.AdminContact.Address[1]);
            Assert.AreEqual("George Town", response.AdminContact.Address[2]);
            Assert.AreEqual("KY1-1108", response.AdminContact.Address[3]);
            Assert.AreEqual("KY", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("tattoo-billing", response.BillingContact.RegistryId);
            Assert.AreEqual("Uniregistry billing contact", response.BillingContact.Name);
            Assert.AreEqual("Uniregistry, Corp", response.BillingContact.Organization);
            Assert.AreEqual("+1.3457496263", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.3457496263", response.BillingContact.FaxNumber);
            Assert.AreEqual("billing@nic.tattoo", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("PO Box 1361", response.BillingContact.Address[0]);
            Assert.AreEqual("Grand Cayman", response.BillingContact.Address[1]);
            Assert.AreEqual("George Town", response.BillingContact.Address[2]);
            Assert.AreEqual("KY1-1108", response.BillingContact.Address[3]);
            Assert.AreEqual("KY", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("tattoo-tech", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Uniregistry tech contact", response.TechnicalContact.Name);
            Assert.AreEqual("Uniregistry, Corp", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.3457496263", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.3457496263", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("tech@nic.tattoo", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("PO Box 1361", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Grand Cayman", response.TechnicalContact.Address[1]);
            Assert.AreEqual("George Town", response.TechnicalContact.Address[2]);
            Assert.AreEqual("KY1-1108", response.TechnicalContact.Address[3]);
            Assert.AreEqual("KY", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("a.ns.uniregistry.net", response.NameServers[0]);
            Assert.AreEqual("tld.isc-sns.info", response.NameServers[1]);
            Assert.AreEqual("tld.isc-sns.com", response.NameServers[2]);
            Assert.AreEqual("tld.isc-sns.net", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[2]);

            Assert.AreEqual("signedDelegation", response.DnsSecStatus);
            Assert.AreEqual(62, response.FieldsParsed);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "unavailable.txt");
            var response = parser.Parse("whois.uniregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.uniregistry.net/tattoo/Unavailable", response.TemplateName);

            Assert.AreEqual("cheap.tattoo", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }
    }
}
