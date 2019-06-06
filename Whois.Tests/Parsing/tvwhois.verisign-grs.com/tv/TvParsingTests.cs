using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Tvwhois.Verisign.Grs.Com.Tv
{
    [TestFixture]
    public class TvParsingTests : ParsingTests
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
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "found.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", "tv", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "not_found.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", "tv", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "found_status_registered.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", "tv", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
