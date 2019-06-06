using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Denic.De.De
{
    [TestFixture]
    public class DeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.denic.de", "de", "found.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_technical_contact()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found_technical_contact.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "error.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Error, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "throttled.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "not_found.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_failed()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "failed.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Failed, response.Status);
        }

        [Test]
        public void Test_failed_status_failed_ace()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "failed_status_failed_ace.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Failed, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "invalid.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found_status_registered.txt");
            var response = parser.Parse("whois.denic.de", "de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
