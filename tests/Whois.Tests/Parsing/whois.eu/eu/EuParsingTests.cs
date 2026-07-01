using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Eu.Eu
{
    [TestFixture]
    public class EuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.eu", "eu", "found.txt");
            var response = parser.Parse("whois.eu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eu/eu/Found", response.TemplateName);

            Assert.AreEqual("eurid.eu", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("EURid vzw/asbl", response.Registrar.Name);
            Assert.AreEqual("www.eurid.eu", response.Registrar.Url);

            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("a.nic.eu", response.NameServers[0]);
            Assert.AreEqual("l.nic.eu", response.NameServers[1]);
            Assert.AreEqual("p.nic.eu", response.NameServers[2]);
            Assert.AreEqual("ns1.eurid.eu", response.NameServers[3]);
            Assert.AreEqual("ns2.eurid.eu", response.NameServers[4]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.eu", "eu", "throttled.txt");
            var response = parser.Parse("whois.eu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eu/eu/Throttled", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.eu", "eu", "not_found.txt");
            var response = parser.Parse("whois.eu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eu/eu/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.eu", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.eu", "eu", "found_status_registered.txt");
            var response = parser.Parse("whois.eu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eu/eu/Found", response.TemplateName);

            Assert.AreEqual("google.eu", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("https://www.markmonitor.com/", response.Registrar.Url);

            Assert.AreEqual(3, response.FieldsParsed);
        }
    }
}
