using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sx.Sx
{
    [TestFixture]
    public class SxParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_premium_name()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "other_status_premium_name.txt");
            var response = parser.Parse("whois.sx", "sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "not_found.txt");
            var response = parser.Parse("whois.sx", "sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "found.txt");
            var response = parser.Parse("whois.sx", "sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.sx", "sx", "unavailable.txt");
            var response = parser.Parse("whois.sx", "sx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unavailable, response.Status);
        }
    }
}
