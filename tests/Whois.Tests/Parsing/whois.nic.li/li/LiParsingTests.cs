using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Li.Li
{
    [TestFixture]
    public class LiParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.li", "li", "not_found.txt");
            var response = parser.Parse("whois.nic.li", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.li/li/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.li", "li", "found.txt");
            var response = parser.Parse("whois.nic.li", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.li/li/Found", response.TemplateName);

            Assert.AreEqual("google.li", response.DomainName.ToString());

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Administrator Domain", response.Registrant.Address[0]);
            Assert.AreEqual("Amphitheatre Parkway 1600", response.Registrant.Address[1]);
            Assert.AreEqual("US-94043 Mountain View, CA", response.Registrant.Address[2]);
            Assert.AreEqual("United States", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Address[0]);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US-94043 Mountain View", response.TechnicalContact.Address[2]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual("N", response.DnsSecStatus);
            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
