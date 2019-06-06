using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Be.Be
{
    [TestFixture]
    public class BeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.be", "be", "found.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "not_found.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "error.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Error, response.Status);
        }

        [Test]
        public void Test_not_available()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "not_available.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotAvailable, response.Status);
        }

        [Test]
        public void Test_out_of_service()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "out_of_service.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.OutOfService, response.Status);
        }

        [Test]
        public void Test_quarantined()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "quarantined.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Quarantined, response.Status);
        }

        [Test]
        public void Test_blocked()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "blocked.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Blocked, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "throttled.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_throttled_response_throttled_limit()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "throttled_response_throttled_limit.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "not_found_status_available.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "invalid.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.be", "be", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.be", "be", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
