using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Qa.Qa
{
    [TestFixture]
    public class QaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.qa", "qa", "found.txt");
            var response = parser.Parse("whois.registry.qa", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.qa/qa/Found", response.TemplateName);

            Assert.AreEqual("qnb.com.qa", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Qatar Telecom (Qtel) Q. S. C", response.Registrar.Name);

             // Registrant Details
            Assert.AreEqual("QT40975", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Administrator - Qtel Internet Services", response.Registrant.Name);


             // TechnicalContact Details
            Assert.AreEqual("QT40975", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Administrator - Qtel Internet Services", response.TechnicalContact.Name);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.qatarbank.com", response.NameServers[0]);
            Assert.AreEqual("ns2.qatarbank.com", response.NameServers[1]);
            Assert.AreEqual("ns3.qatarbank.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("serverDeleteProhibited (Legacy)", response.DomainStatus[0]);
            Assert.AreEqual("serverRenewProhibited (Legacy)", response.DomainStatus[1]);
            Assert.AreEqual("serverTransferProhibited (Legacy)", response.DomainStatus[2]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registry.qa", "qa", "not_found.txt");
            var response = parser.Parse("whois.registry.qa", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.qa/qa/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.registry.qa", "qa", "found_status_registered.txt");
            var response = parser.Parse("whois.registry.qa", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registry.qa/qa/Found", response.TemplateName);

            Assert.AreEqual("qtel.com.qa", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Qatar Telecom (Qtel) Q. S. C", response.Registrar.Name);


             // Registrant Details
            Assert.AreEqual("QT11734", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Administrator - Qtel Internet Services", response.Registrant.Name);


             // TechnicalContact Details
            Assert.AreEqual("QT11734", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Administrator - Qtel Internet Services", response.TechnicalContact.Name);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.qtel.com.qa", response.NameServers[0]);
            Assert.AreEqual("ns2.qtel.com.qa", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
