using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Coza.Whois.Registry.Net.Za.CoZa
{
    [TestFixture]
    public class CoZaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found.txt");
            var response = parser.Parse("coza-whois.registry.net.za", "co.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "throttled.txt");
            var response = parser.Parse("coza-whois.registry.net.za", "co.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "not_found.txt");
            var response = parser.Parse("coza-whois.registry.net.za", "co.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found_status_registered.txt");
            var response = parser.Parse("coza-whois.registry.net.za", "co.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
