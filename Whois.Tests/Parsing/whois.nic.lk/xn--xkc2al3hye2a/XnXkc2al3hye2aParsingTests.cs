using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.XnXkc2al3hye2a
{
    [TestFixture]
    [Ignore("TODO")]
    public class XnXkc2al3hye2aParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.lk", "xn--xkc2al3hye2a", "not_found.txt");
            var response = parser.Parse("whois.nic.lk", "xn--xkc2al3hye2a", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "xn--xkc2al3hye2a", "found.txt");
            var response = parser.Parse("whois.nic.lk", "xn--xkc2al3hye2a", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
