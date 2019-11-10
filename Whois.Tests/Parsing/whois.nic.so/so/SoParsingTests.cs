using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.So.So
{
    [TestFixture]
    public class SoParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.so", "so", "not_found.txt");
            var response = parser.Parse("whois.nic.so", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.so/so/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.so", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.so", "so", "found.txt");
            var response = parser.Parse("whois.nic.so", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.so/so/Found", response.TemplateName);

            Assert.AreEqual("google.so", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 01, 25, 04, 20, 26, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 01, 24, 02, 22, 24, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 01, 24, 02, 22, 24, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("mm-google", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("mm-google", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("so-mm-billing", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("mm-google", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual(16, response.FieldsParsed);
        }
    }
}
