using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tld.Ee.Ee
{
    [TestFixture]
    [Ignore("TODO")]
    public class EeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_serverhold()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "other_status_serverhold.txt");
            var response = parser.Parse("whois.tld.ee", "ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "not_found.txt");
            var response = parser.Parse("whois.tld.ee", "ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "expired.txt");
            var response = parser.Parse("whois.tld.ee", "ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Expired, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tld.ee", "ee", "found.txt");
            var response = parser.Parse("whois.tld.ee", "ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
