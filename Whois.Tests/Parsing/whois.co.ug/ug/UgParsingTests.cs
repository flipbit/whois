using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Ug.Ug
{
    [TestFixture]
    [Ignore("TODO")]
    public class UgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.co.ug", "ug", "found.txt");
            var response = parser.Parse("whois.co.ug", "ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_unconfirmed()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "unconfirmed.txt");
            var response = parser.Parse("whois.co.ug", "ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unconfirmed, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "not_found.txt");
            var response = parser.Parse("whois.co.ug", "ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "found_status_registered.txt");
            var response = parser.Parse("whois.co.ug", "ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
