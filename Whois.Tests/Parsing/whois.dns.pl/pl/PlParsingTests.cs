using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Pl.Pl
{
    [TestFixture]
    public class PlParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found.txt");
            var response = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "throttled.txt");
            var response = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "not_found.txt");
            var response = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
