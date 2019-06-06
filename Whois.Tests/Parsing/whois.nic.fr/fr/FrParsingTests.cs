using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fr.Fr
{
    [TestFixture]
    public class FrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_without_changed()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_contact_without_changed.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_nameservers.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_multiple_ipv4()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_nameservers_multiple_ipv4.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_with_ipv4_and_some_ipv6()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_nameservers_with_ipv4_and_some_ipv6.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_status_active()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_status_active.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_blocked()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "blocked.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Blocked, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not_found.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_other_status_not_open()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "other_status_not_open.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_redemption()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "redemption.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Redemption, response.Status);
        }

        [Test]
        public void Test_not_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not_found_status_registered.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_response_contains_contact_remarks()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_response_contains_contact_remarks.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_response_contains_contact_trouble()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_response_contains_contact_trouble.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "throttled.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.fr", "fr", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.fr", "fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
