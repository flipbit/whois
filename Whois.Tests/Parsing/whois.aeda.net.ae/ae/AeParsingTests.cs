using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Aeda.Net.Ae.Ae
{
    [TestFixture]
    public class AeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.aeda.net.ae", "ae", "not_found.txt");
            var response = parser.Parse("whois.aeda.net.ae", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.aeda.net.ae", "ae", "found.txt");
            var response = parser.Parse("whois.aeda.net.ae", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(11, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("google.ae", response.DomainName.ToString());

            Assert.AreEqual("MarkMonitor", response.Registrar.Name);

            Assert.AreEqual("GOOGLE", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

            Assert.AreEqual("GOOGLE", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);


            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
        }
    }
}
