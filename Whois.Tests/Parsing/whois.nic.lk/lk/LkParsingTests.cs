using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.Lk
{
    [TestFixture]
    [Ignore("TODO")]
    public class LkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.lk", "lk", "found.txt");
            var response = parser.Parse("whois.nic.lk", "lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_found_updated_on_null()
        {
            var sample = SampleReader.Read("whois.nic.lk", "lk", "found_updated_on_null.txt");
            var response = parser.Parse("whois.nic.lk", "lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "lk", "not_found.txt");
            var response = parser.Parse("whois.nic.lk", "lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.lk", "lk", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.lk", "lk", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
