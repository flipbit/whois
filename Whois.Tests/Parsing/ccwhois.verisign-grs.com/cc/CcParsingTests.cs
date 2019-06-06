using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Ccwhois.Verisign.Grs.Com.Cc
{
    [TestFixture]
    public class CcParsingTests : ParsingTests
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
            var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "found.txt");
            var response = parser.Parse("ccwhois.verisign-grs.com", "cc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "not_found.txt");
            var response = parser.Parse("ccwhois.verisign-grs.com", "cc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "found_status_registered.txt");
            var response = parser.Parse("ccwhois.verisign-grs.com", "cc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
