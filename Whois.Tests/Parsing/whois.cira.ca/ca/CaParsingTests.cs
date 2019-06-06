using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cira.Ca.Ca
{
    [TestFixture]
    public class CaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cira.ca", "ca", "found.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_assigned.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotAssigned, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_found.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "pending_delete.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.PendingDelete, response.Status);
        }

        [Test]
        public void Test_redemption()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "redemption.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Redemption, response.Status);
        }

        [Test]
        public void Test_not_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_found_status_registered.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_to_be_released()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "to_be_released.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.ToBeReleased, response.Status);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "unavailable.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Unavailable, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "not_found_status_available.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "invalid.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Invalid, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cira.ca", "ca", "found_status_registered.txt");
            var response = parser.Parse("whois.cira.ca", "ca", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
