using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Isoc.Org.Il.Il
{
    [TestFixture]
    public class IlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "not_found.txt");
            var response = parser.Parse("whois.isoc.org.il", "il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_other_status_transfer_allowed()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "other_status_transfer_allowed.txt");
            var response = parser.Parse("whois.isoc.org.il", "il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_locked()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "locked.txt");
            var response = parser.Parse("whois.isoc.org.il", "il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Locked, response.Status);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "not_found_status_available.txt");
            var response = parser.Parse("whois.isoc.org.il", "il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.isoc.org.il", "il", "found.txt");
            var response = parser.Parse("whois.isoc.org.il", "il", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
