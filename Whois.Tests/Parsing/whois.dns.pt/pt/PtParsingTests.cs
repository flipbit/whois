using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Pt.Pt
{
    [TestFixture]
    public class PtParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found.txt");
            var response = parser.Parse("whois.dns.pt", "pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_other_status_techpro()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "other_status_techpro.txt");
            var response = parser.Parse("whois.dns.pt", "pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "not_found.txt");
            var response = parser.Parse("whois.dns.pt", "pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "inactive.txt");
            var response = parser.Parse("whois.dns.pt", "pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Inactive, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.pt", "pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.dns.pt", "pt", "reserved.txt");
            var response = parser.Parse("whois.dns.pt", "pt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }
    }
}
