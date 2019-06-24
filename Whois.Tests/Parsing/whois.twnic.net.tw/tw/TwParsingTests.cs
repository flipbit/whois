using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Twnic.Net.Tw.Tw
{
    [TestFixture]
    [Ignore("TODO")]
    public class TwParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.twnic.net.tw", "tw", "not_found.txt");
            var response = parser.Parse("whois.twnic.net.tw", "tw", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.twnic.net.tw", "tw", "found.txt");
            var response = parser.Parse("whois.twnic.net.tw", "tw", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
