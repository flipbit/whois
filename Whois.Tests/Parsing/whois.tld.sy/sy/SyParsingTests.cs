using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tld.Sy.Sy
{
    [TestFixture]
    public class SyParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.tld.sy", "sy", "not_found.txt");
            var response = parser.Parse("whois.tld.sy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.sy", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tld.sy", "sy", "found.txt");
            var response = parser.Parse("whois.tld.sy", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("tld.sy", response.DomainName.ToString());
            Assert.AreEqual("7-sy", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("nans", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 12, 02, 16, 01, 27, 664, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 12, 01, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("6714-sy", response.Registrant.RegistryId);
            Assert.AreEqual("domain@tld.sy", response.Registrant.Email);


             // BillingContact Details
            Assert.AreEqual("6714-sy", response.BillingContact.RegistryId);
            Assert.AreEqual("domain@tld.sy", response.BillingContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns4.tld.sy", response.NameServers[0]);
            Assert.AreEqual("ns3.tld.sy", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(14, response.FieldsParsed);
        }
    }
}
