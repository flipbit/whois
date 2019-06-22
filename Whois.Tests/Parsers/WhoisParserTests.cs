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
        public void TestParsePlRecord()
        {
            var sample = sampleReader.Read("whois.dns.pl", "pl", "08.pl.txt");

            var record = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.AreEqual("08.pl", record.DomainName);
        }

        [Test]
        public void TestParseJpRecord()
        {
            var sample = sampleReader.Read("whois.jprs.jp", "jp", "amazon.co.jp.txt");

            var record = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.AreEqual("amazon.co.jp", record.DomainName);
            Assert.AreEqual("Amazon, Inc.", record.Registrant.Name);
            Assert.AreEqual("JC076JP", record.AdminContact.Name);
            Assert.AreEqual("IK4644JP", record.TechnicalContact.Name);
            Assert.AreEqual(4, record.NameServers.Count);
            Assert.AreEqual("ns1.p31.dynect.net", record.NameServers[0]);
            Assert.AreEqual("ns2.p31.dynect.net", record.NameServers[1]);
            Assert.AreEqual("pdns1.ultradns.net", record.NameServers[2]);
            Assert.AreEqual("pdns6.ultradns.co.uk", record.NameServers[3]);
            Assert.AreEqual(new DateTime(2002, 11, 21), record.Registered);
            Assert.AreEqual(new DateTime(2018, 12, 01), record.Updated);
        }
        
        [Test]
        public void TestParseDeRecord()
        {
            var sample = sampleReader.Read("whois.denic.de", "de", "amazon.de.txt");
            
            var record = parser.Parse("whois.denic.de", "de", sample);

            Assert.AreEqual("amazon.de", record.DomainName);
        }

        [Test]
        public void TestParseJpAltRecord()
        {
            var sample = sampleReader.Read("whois.jprs.jp", "jp", "ameblo.jp.txt");
            
            var record = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.AreEqual("ameblo.jp", record.DomainName);
            Assert.AreEqual("CyberAgent, Inc.", record.Registrant.Name);
            Assert.AreEqual(6, record.NameServers.Count);
            Assert.AreEqual("a1-5.akam.net", record.NameServers[0]);
            Assert.AreEqual("a11-66.akam.net", record.NameServers[1]);
            Assert.AreEqual("a20-67.akam.net", record.NameServers[2]);
            Assert.AreEqual("a4-64.akam.net", record.NameServers[3]);
            Assert.AreEqual("a6-65.akam.net", record.NameServers[4]);
            Assert.AreEqual("a7-66.akam.net", record.NameServers[5]);
            Assert.AreEqual(new DateTime(2004, 7, 30), record.Registered);
            Assert.AreEqual(new DateTime(2019, 7, 31), record.Expiration);
            Assert.AreEqual(new DateTime(2018, 8, 1), record.Updated);
            Assert.AreEqual("CyberAgent, Inc.", record.AdminContact.Name);
            Assert.AreEqual("dns-ssl-info@cyberagent.co.jp", record.AdminContact.Email);
            Assert.AreEqual(3, record.AdminContact.Address.Count);
            Assert.AreEqual("Shibuya-ku", record.AdminContact.Address[0]);
            Assert.AreEqual("19-1 Maruyamacho", record.AdminContact.Address[1]);
            Assert.AreEqual("Shibuya Prime Plaza 2F", record.AdminContact.Address[2]);
            Assert.AreEqual("03-5459-6150", record.AdminContact.TelephoneNumber);
            Assert.AreEqual("03-5784-7070", record.AdminContact.FaxNumber);
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
