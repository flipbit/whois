using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nc.Nc
{
    [TestFixture]
    [Ignore("TODO")]
    public class NcParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nc", "nc", "found.txt");
            var response = parser.Parse("whois.nc", "nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_contact_without_state_and_address()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found_contact_without_state_and_address.txt");
            var response = parser.Parse("whois.nc", "nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "not_found.txt");
            var response = parser.Parse("whois.nc", "nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nc", "nc", "found_status_registered.txt");
            var response = parser.Parse("whois.nc", "nc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
