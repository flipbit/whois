using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domain.Registry.Nl.Nl
{
    [TestFixture]
    public class NlParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "found.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "not_assigned.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotAssigned, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "throttled.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_throttled_response_throttled_daily()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "throttled_response_throttled_daily.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "unavailable.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unavailable, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "not_found.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_redemption()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "redemption.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Redemption, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "found_status_registered.txt");
            var response = parser.Parse("whois.domain-registry.nl", "nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
