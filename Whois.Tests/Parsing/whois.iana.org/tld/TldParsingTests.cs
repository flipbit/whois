using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iana.Org.Tld
{
    [TestFixture]
    public class TldParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.iana.org", "tld", "not_assigned.txt");
            var response = parser.Parse("whois.iana.org", "tld", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotAssigned, response.Status);
        }
    }
}
