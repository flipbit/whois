using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Srs.Net.Nz.Nz
{
    [TestFixture]
    public class NzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_pendingrelease()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "other_status_pendingrelease.txt");
            var response = parser.Parse("whois.srs.net.nz", "nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "throttled.txt");
            var response = parser.Parse("whois.srs.net.nz", "nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "not_found.txt");
            var response = parser.Parse("whois.srs.net.nz", "nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "invalid.txt");
            var response = parser.Parse("whois.srs.net.nz", "nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found.txt");
            var response = parser.Parse("whois.srs.net.nz", "nz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
