using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tr.Tr
{
    [TestFixture]
    [Ignore("TODO")]
    public class TrParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_person()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_contact_person.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_with_trailing_space()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_nameservers_with_trailing_space.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrant_contact_outside_cityinoneline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_cityinoneline.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrant_contact_outside_citynextline()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_outside_citynextline.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrant_contact_turkey()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_registrant_contact_turkey.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "error.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Error, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "not_found.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "invalid.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.tr", "tr", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.tr", "tr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
