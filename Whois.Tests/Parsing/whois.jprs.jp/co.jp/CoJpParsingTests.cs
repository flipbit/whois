using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.CoJp
{
    [TestFixture]
    public class CoJpParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "pending_delete.txt");
            var response = parser.Parse("whois.jprs.jp", "co.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.PendingDelete, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "co.jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", "co.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
