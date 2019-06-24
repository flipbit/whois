using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tznic.Or.Tz.Tz
{
    [TestFixture]
    [Ignore("TODO")]
    public class TzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "expired.txt");
            var response = parser.Parse("whois.tznic.or.tz", "tz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Expired, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "not_found.txt");
            var response = parser.Parse("whois.tznic.or.tz", "tz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "found.txt");
            var response = parser.Parse("whois.tznic.or.tz", "tz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
