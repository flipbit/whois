using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.NeJp
{
    [TestFixture]
    [Ignore("TODO")]
    public class NeJpParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", "ne.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved.txt");
            var response = parser.Parse("whois.jprs.jp", "ne.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "not_found.txt");
            var response = parser.Parse("whois.jprs.jp", "ne.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found_status_registered.txt");
            var response = parser.Parse("whois.jprs.jp", "ne.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved_status_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved_status_reserved.txt");
            var response = parser.Parse("whois.jprs.jp", "ne.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }
    }
}
