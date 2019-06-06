using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Net.Pro
{
    [TestFixture]
    public class ProParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.afilias.net", "pro", "not_found.txt");
            var response = parser.Parse("whois.afilias.net", "pro", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias.net", "pro", "found.txt");
            var response = parser.Parse("whois.afilias.net", "pro", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.afilias.net", "pro", "reserved.txt");
            var response = parser.Parse("whois.afilias.net", "pro", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }
    }
}
