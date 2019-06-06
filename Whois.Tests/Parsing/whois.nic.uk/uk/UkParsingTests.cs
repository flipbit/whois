using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Uk.Uk
{
    [TestFixture]
    public class UkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrant_type_individual()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrant_type_individual.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrant_type_unknown()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrant_type_unknown.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrar_godaddy()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrar_godaddy.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_registrar_without_trading_name()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_registrar_without_trading_name.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "not_found.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_other_status_no_longer_required()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_no_longer_required.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_no_status_listed()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_no_status_listed.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_processing_registration()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_processing_registration.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_processing_renewal()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_processing_renewal.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_other_status_registered_until_expiry_date()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "other_status_registered_until_expiry_date.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "suspended.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "throttled.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "invalid.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "reserved.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }

        [Test]
        public void Test_suspended_status_suspended()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "suspended_status_suspended.txt");
            var response = parser.Parse("whois.nic.uk", "uk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);
        }
    }
}
