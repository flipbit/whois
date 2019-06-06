using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Om.Om
{
    [TestFixture]
    public class OmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registry.om", "om", "not_found.txt");
            var response = parser.Parse("whois.registry.om", "om", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "found.txt");
            var response = parser.Parse("whois.registry.om", "om", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "reserved.txt");
            var response = parser.Parse("whois.registry.om", "om", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Reserved, response.Status);
        }
    }
}
