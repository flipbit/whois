using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Name.Name
{
    [TestFixture]
    public class NameParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.name", "name", "reserved.txt");
            var response = parser.Parse("whois.nic.name", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.name/name/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.name", "name", "not_found.txt");
            var response = parser.Parse("whois.nic.name", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.name/name/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.name", response.DomainName.ToString());
            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.name", "name", "found.txt");
            var response = parser.Parse("whois.nic.name", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.name/name/Found", response.TemplateName);

            Assert.AreEqual("carletti.name", response.DomainName.ToString());
            Assert.AreEqual("2788515_DOMAIN_NAME-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("eNom, Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 11, 30, 18, 51, 55, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 04, 19, 12, 22, 08, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 04, 19, 12, 22, 08, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("7903395_CONTACT_NAME-VRSN", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("10919759_CONTACT_NAME-VRSN", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("10919759_CONTACT_NAME-VRSN", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("10919759_CONTACT_NAME-VRSN", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.dnsimple.com", response.NameServers[0]);
            Assert.AreEqual("ns2.dnsimple.com", response.NameServers[1]);
            Assert.AreEqual("ns3.dnsimple.com", response.NameServers[2]);
            Assert.AreEqual("ns4.dnsimple.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }
    }
}
