using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iis.Se.Se
{
    [TestFixture]
    [Ignore("TODO")]
    public class SeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.iis.se", "se", "found.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_single()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_nameservers_single.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "not_assigned.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotAssigned, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "not_found.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_status_ok.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_other_status_serverhold()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "other_status_serverhold.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "not_found_status_available.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_status_registered.txt");
            var response = parser.Parse("whois.iis.se", "se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
