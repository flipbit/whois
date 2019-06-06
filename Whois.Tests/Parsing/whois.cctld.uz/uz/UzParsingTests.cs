using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cctld.Uz.Uz
{
    [TestFixture]
    public class UzParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "found.txt");
            var response = parser.Parse("whois.cctld.uz", "uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "reserved.txt");
            var response = parser.Parse("whois.cctld.uz", "uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "not_found.txt");
            var response = parser.Parse("whois.cctld.uz", "uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "found_status_registered.txt");
            var response = parser.Parse("whois.cctld.uz", "uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
