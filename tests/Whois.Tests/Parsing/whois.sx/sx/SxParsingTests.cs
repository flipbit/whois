using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sx.Sx
{
    [TestFixture]
    public class SxParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_premium_name()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "other_status_premium_name.txt");
            var response = parser.Parse("whois.sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sx/sx/Unavailable", response.TemplateName);

            Assert.AreEqual("domain.sx", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "not_found.txt");
            var response = parser.Parse("whois.sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sx/sx/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.sx", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "found.txt");
            var response = parser.Parse("whois.sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("whois.sx", response.DomainName.ToString());
            Assert.AreEqual("d5-sx", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("SX Registry O", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 02, 25, 16, 50, 39, 204, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 12, 09, 14, 07, 22, 794, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2022, 12, 09, 14, 07, 22, 794, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("C65", response.Registrant.RegistryId);
            Assert.AreEqual("SX Registry SA administrator", response.Registrant.Name);
            Assert.AreEqual("SX Registry SA", response.Registrant.Organization);
            Assert.AreEqual("registry@registry.sx", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("2, rue Léon Laval", response.Registrant.Address[0]);
            Assert.AreEqual("Leudelange", response.Registrant.Address[1]);
            Assert.AreEqual("L3372", response.Registrant.Address[2]);
            Assert.AreEqual("LUXEMBOURG", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("C65", response.AdminContact.RegistryId);
            Assert.AreEqual("SX Registry SA administrator", response.AdminContact.Name);
            Assert.AreEqual("SX Registry SA", response.AdminContact.Organization);
            Assert.AreEqual("registry@registry.sx", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("2, rue Léon Laval", response.AdminContact.Address[0]);
            Assert.AreEqual("Leudelange", response.AdminContact.Address[1]);
            Assert.AreEqual("L3372", response.AdminContact.Address[2]);
            Assert.AreEqual("LUXEMBOURG", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("C65", response.TechnicalContact.RegistryId);
            Assert.AreEqual("SX Registry SA administrator", response.TechnicalContact.Name);
            Assert.AreEqual("SX Registry SA", response.TechnicalContact.Organization);
            Assert.AreEqual("registry@registry.sx", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2, rue Léon Laval", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Leudelange", response.TechnicalContact.Address[1]);
            Assert.AreEqual("L3372", response.TechnicalContact.Address[2]);
            Assert.AreEqual("LUXEMBOURG", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("a.ns.sx", response.NameServers[0]);
            Assert.AreEqual("b.ns.sx", response.NameServers[1]);
            Assert.AreEqual("c.ns.sx", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("signedDelegation", response.DnsSecStatus);
            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "unavailable.txt");
            var response = parser.Parse("whois.sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.sx/sx/Unavailable", response.TemplateName);

            Assert.AreEqual("domain.sx", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }
    }
}
