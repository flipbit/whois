using NUnit.Framework;

namespace Whois.Parsers
{
    [TestFixture]
    public class WhoisParserTests
    {
        private WhoisParser parser;
        private SampleReader sampleReader;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
            sampleReader = new SampleReader();
        }

        [Test]
        public void TestParseDomainNameWhois()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            var result = parser.Parse("capetown-whois.registry.net.za", sample);

            Assert.IsNotNull(result);
            Assert.AreEqual("registry.capetown", result.DomainName.ToString());
            Assert.AreEqual(WhoisStatus.Found, result.Status);
            Assert.AreEqual(2, parser.Templates.Names.Count);
        }

        [Test]
        public void TestParseDomainNameWhoisDoesNotRegisterTemplateTwice()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            parser.Parse("capetown-whois.registry.net.za", sample);
            parser.Parse("capetown-whois.registry.net.za", sample);

            Assert.AreEqual(2, parser.Templates.Names.Count);
        }
    }
}
