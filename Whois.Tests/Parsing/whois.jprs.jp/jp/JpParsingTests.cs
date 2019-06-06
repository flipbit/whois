using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.Jp
{
    [TestFixture]
    public class JpParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "suspended.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);
        }

        [Test]
        public void Test_other_status_to_be_suspended()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "other_status_to_be_suspended.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Other, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "not_found.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "found_status_registered.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "jp", "reserved.txt");
            var response = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }
    }
}
