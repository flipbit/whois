using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kenic.Or.Ke.Ke
{
    [TestFixture]
    [Ignore("TODO")]
    public class KeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "not_found.txt");
            var response = parser.Parse("whois.kenic.or.ke", "ke", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "invalid.txt");
            var response = parser.Parse("whois.kenic.or.ke", "ke", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "found.txt");
            var response = parser.Parse("whois.kenic.or.ke", "ke", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
