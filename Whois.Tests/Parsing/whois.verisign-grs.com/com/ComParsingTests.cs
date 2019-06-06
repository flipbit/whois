using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Verisign.Grs.Com.Com
{
    [TestFixture]
    public class ComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "pending_delete.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.PendingDelete, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "not_found.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
