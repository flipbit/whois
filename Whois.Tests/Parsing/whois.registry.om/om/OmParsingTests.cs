using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Om.Om
{
    [TestFixture]
    public class OmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registry.om", "om", "not_found.txt");
            var response = parser.Parse("whois.registry.om", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.om/om/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "found.txt");
            var response = parser.Parse("whois.registry.om", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.om/om/Found", response.TemplateName);

            Assert.AreEqual("rop.gov.om", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Oman Telecommunication Company", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 10, 06, 18, 20, 12, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.AreEqual("10084244", response.Registrant.RegistryId);
            Assert.AreEqual("Nasser Said Al Daree", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("Mina Al Fahal", response.Registrant.Address[0]);
            Assert.AreEqual("om", response.Registrant.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("10084244", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Nasser Said Al Daree", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Mina Al Fahal", response.TechnicalContact.Address[0]);
            Assert.AreEqual("om", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns3.omantel.net.om", response.NameServers[0]);
            Assert.AreEqual("ns1.omantel.net.om", response.NameServers[1]);
            Assert.AreEqual("ns2.omantel.net.om", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "reserved.txt");
            var response = parser.Parse("whois.registry.om", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.om/om/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }
    }
}
