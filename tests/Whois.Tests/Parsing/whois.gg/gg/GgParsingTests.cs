using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Gg.Gg
{
    [TestFixture]
    public class GgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.gg", "gg", "not_found.txt");
            var response = parser.Parse("whois.gg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.gg", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.gg", "gg", "found.txt");
            var response = parser.Parse("whois.gg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.gg", response.DomainName.ToString());
            Assert.AreEqual("24221-CI", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.gg", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2003, 04, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("32764-CI", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("32764-CI", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("32762-CI", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("32764-CI", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns4.google.com", response.NameServers[2]);
            Assert.AreEqual("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("ok", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[3]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(20, response.FieldsParsed);
        }
    }
}
