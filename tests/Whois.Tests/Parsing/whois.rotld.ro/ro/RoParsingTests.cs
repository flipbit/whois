using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Rotld.Ro.Ro
{
    [TestFixture]
    public class RoParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_updateprohibited()
        {
            var sample = SampleReader.Read("whois.rotld.ro", "ro", "other_status_updateprohibited.txt");
            var response = parser.Parse("whois.rotld.ro", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rotld.ro/ro/Found", response.TemplateName);

            Assert.AreEqual("google.ro", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2000, 07, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns4.google.com", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("UpdateProhibited", response.DomainStatus[0]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.rotld.ro", "ro", "not_found.txt");
            var response = parser.Parse("whois.rotld.ro", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rotld.ro/ro/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.rotld.ro", "ro", "found.txt");
            var response = parser.Parse("whois.rotld.ro", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.rotld.ro/ro/Found", response.TemplateName);

            Assert.AreEqual("google.ro", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2000, 07, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("UpdateProhibited", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
