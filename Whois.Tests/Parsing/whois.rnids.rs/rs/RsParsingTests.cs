using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Rnids.Rs.Rs
{
    [TestFixture]
    public class RsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "found.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_nameservers_hyphenated()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "found_nameservers_hyphenated.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "expired.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Expired, response.Status);
        }

        [Test]
        public void Test_other_status_in_transfer()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "other_status_in_transfer.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_locked()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "locked.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Locked, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "not_found.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.rnids.rs", "rs", "found_status_registered.txt");
            var response = parser.Parse("whois.rnids.rs", "rs", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
