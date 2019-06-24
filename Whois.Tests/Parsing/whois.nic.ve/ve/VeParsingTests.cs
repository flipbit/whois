using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ve.Ve
{
    [TestFixture]
    [Ignore("TODO")]
    public class VeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_nameservers.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_missing()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_nameservers_missing.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_status_activo()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_status_activo.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "not_found.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "suspended.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);
        }

        [Test]
        public void Test_found_updated_on()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_updated_on.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_updated_on_blank()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_updated_on_blank.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "inactive.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Inactive, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.ve", "ve", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.ve", "ve", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
