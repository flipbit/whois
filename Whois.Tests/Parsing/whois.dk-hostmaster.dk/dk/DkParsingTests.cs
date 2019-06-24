using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dk.Hostmaster.Dk.Dk
{
    [TestFixture]
    [Ignore("TODO")]
    public class DkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_deactivated()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "deactivated.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", "dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Deactivated, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "reserved.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", "dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "throttled.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", "dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_throttled_response_throttled()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "throttled_response_throttled.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", "dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "not_found.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", "dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dk-hostmaster.dk", "dk", "found.txt");
            var response = parser.Parse("whois.dk-hostmaster.dk", "dk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
