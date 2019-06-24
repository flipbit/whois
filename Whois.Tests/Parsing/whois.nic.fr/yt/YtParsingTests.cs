using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fr.Yt
{
    [TestFixture]
    [Ignore("TODO")]
    public class YtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.fr", "yt", "throttled.txt");
            var response = parser.Parse("whois.nic.fr", "yt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "yt", "not_found.txt");
            var response = parser.Parse("whois.nic.fr", "yt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "yt", "found.txt");
            var response = parser.Parse("whois.nic.fr", "yt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
