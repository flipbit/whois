using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cat.Cat
{
    [TestFixture]
    public class CatParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cat", "cat", "not_found.txt");
            var response = parser.Parse("whois.cat", "cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found.txt");
            var response = parser.Parse("whois.cat", "cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found_status_ok.txt");
            var response = parser.Parse("whois.cat", "cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "not_found_status_available.txt");
            var response = parser.Parse("whois.cat", "cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cat", "cat", "found_status_registered.txt");
            var response = parser.Parse("whois.cat", "cat", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
