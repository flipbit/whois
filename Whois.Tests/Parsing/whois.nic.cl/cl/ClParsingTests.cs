using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cl.Cl
{
    [TestFixture]
    public class ClParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.cl", "cl", "not_found.txt");
            var response = parser.Parse("whois.nic.cl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cl/cl/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.cl", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.cl", "cl", "found.txt");
            var response = parser.Parse("whois.nic.cl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cl/cl/Found", response.TemplateName);

            Assert.AreEqual("google.cl", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("Google Inc. Representada por NameAction Chile S.A. (ASESORIAS NAMEACTION CHILE LIMITADA)", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("Markmonitor Tech", response.AdminContact.Name);
            Assert.AreEqual("Markmonitor", response.AdminContact.Organization);


             // TechnicalContact Details
            Assert.AreEqual("Markmonitor Tech", response.TechnicalContact.Name);
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Organization);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns3.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns1.google.com", response.NameServers[2]);
            Assert.AreEqual("ns2.google.com", response.NameServers[3]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
