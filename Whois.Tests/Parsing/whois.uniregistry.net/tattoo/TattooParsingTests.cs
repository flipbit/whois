using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Uniregistry.Net.Tattoo
{
    [TestFixture]
    public class TattooParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "not_found.txt");
            var response = parser.Parse("whois.uniregistry.net", "tattoo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "found.txt");
            var response = parser.Parse("whois.uniregistry.net", "tattoo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "unavailable.txt");
            var response = parser.Parse("whois.uniregistry.net", "tattoo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unavailable, response.Status);
        }
    }
}
