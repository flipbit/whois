using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Org.Whois.Registry.Net.Za.OrgZa
{
    [TestFixture]
    public class OrgZaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("org-whois.registry.net.za", "org.za", "not_found.txt");
            var response = parser.Parse("org-whois.registry.net.za", "org.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("org-whois.registry.net.za", "org.za", "found.txt");
            var response = parser.Parse("org-whois.registry.net.za", "org.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);
        }
    }
}
