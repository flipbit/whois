using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Kero.Yachay.Pe.Pe
{
    [TestFixture]
    public class PeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "throttled.txt");
            var response = parser.Parse("kero.yachay.pe", "pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "not_found.txt");
            var response = parser.Parse("kero.yachay.pe", "pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "inactive.txt");
            var response = parser.Parse("kero.yachay.pe", "pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Inactive, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "found.txt");
            var response = parser.Parse("kero.yachay.pe", "pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "suspended.txt");
            var response = parser.Parse("kero.yachay.pe", "pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);
        }
    }
}
