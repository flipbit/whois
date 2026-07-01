using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lv.Lv
{
    [TestFixture]
    public class LvParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.lv", "lv", "not_found.txt");
            var response = parser.Parse("whois.nic.lv", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lv/lv/Found", response.TemplateName);

            Assert.AreEqual("u34jedzcq.lv", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("free", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.lv", "lv", "found.txt");
            var response = parser.Parse("whois.nic.lv", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.lv/lv/Found", response.TemplateName);

            Assert.AreEqual("google.lv", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+12083895740", response.Registrar.AbuseTelephoneNumber);


             // Registrant Details
            Assert.AreEqual("Google, Inc.", response.Registrant.Name);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA", response.Registrant.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("+12083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+12083895799", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }
    }
}
