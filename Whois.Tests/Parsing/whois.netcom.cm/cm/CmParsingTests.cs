using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Netcom.Cm.Cm
{
    [TestFixture]
    [Ignore("TODO")]
    public class CmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "not_found.txt");
            var response = parser.Parse("whois.netcom.cm", "cm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "found.txt");
            var response = parser.Parse("whois.netcom.cm", "cm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "suspended.txt");
            var response = parser.Parse("whois.netcom.cm", "cm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Suspended, response.Status);
        }
    }
}
