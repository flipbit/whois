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
            Assert.AreEqual(5, parser.Templates.Count);
        }

        [Test]
        public void TestParseDomainNameWhoisDoesNotRegisterTemplateTwice()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            parser.Parse("capetown-whois.registry.net.za", "capetown", sample);
            parser.Parse("capetown-whois.registry.net.za", "capetown", sample);

            Assert.AreEqual(5, parser.Templates.Count);
        }

        [Test]
        public void TestParseCzRecord()
        {
            var sample = sampleReader.Read("whois.nic.cz", "cz", "phoca.cz.txt");
            
            var record = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.AreEqual("CZ.NIC", record.TemplateName);

            Assert.AreEqual("phoca.cz", record.DomainName);

            Assert.AreEqual("REG-ZONER", record.Registrar.Name);

            Assert.AreEqual(new DateTime(2007, 8, 8, 7, 15, 0), record.Registered);
            Assert.AreEqual(new DateTime(2012, 4, 4, 4, 37, 56), record.Updated);
            Assert.AreEqual(new DateTime(2019, 8, 8), record.Expiration);
        }
    }
}
