using NUnit.Framework;
using System;
using Whois.Models;

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

            var result = parser.Parse("capetown-whois.registry.net.za", "capetown", sample);

            Assert.IsNotNull(result);
            Assert.AreEqual("registry.capetown", result.DomainName);
            Assert.AreEqual(WhoisResponseStatus.Found, result.Status);
            Assert.AreEqual(2, parser.Templates.Count);
        }

        [Test]
        public void TestParseDomainNameWhoisDoesNotRegisterTemplateTwice()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            parser.Parse("capetown-whois.registry.net.za", "capetown", sample);
            parser.Parse("capetown-whois.registry.net.za", "capetown", sample);

            Assert.AreEqual(2, parser.Templates.Count);
        }
    }
}
