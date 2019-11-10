using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cd.Cd
{
    [TestFixture]
    public class CdParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.cd", "cd", "not_found.txt");
            var response = parser.Parse("whois.nic.cd", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cd/cd/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.cd", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Available", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.cd", "cd", "found.txt");
            var response = parser.Parse("whois.nic.cd", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cd/cd/Found", response.TemplateName);

            Assert.AreEqual("google.cd", response.DomainName.ToString());
            Assert.AreEqual("5758-CD", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MARKMONITOR", response.Registrar.Name);


            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(5, response.FieldsParsed);
        }
    }
}
