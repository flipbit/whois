using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Coop.Coop
{
    [TestFixture]
    [Ignore("TODO")]
    public class CoopParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found.txt");
            var response = parser.Parse("whois.nic.coop", "coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "other_status_single.txt");
            var response = parser.Parse("whois.nic.coop", "coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "not_found.txt");
            var response = parser.Parse("whois.nic.coop", "coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.coop", "coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
