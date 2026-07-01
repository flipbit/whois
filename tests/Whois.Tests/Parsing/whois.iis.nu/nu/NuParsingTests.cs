using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iis.Nu.Nu
{
    [TestFixture]
    public class NuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.iis.nu", "nu", "not_found.txt");
            var response = parser.Parse("whois.iis.nu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.nu/nu/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.nu", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.iis.nu", "nu", "found.txt");
            var response = parser.Parse("whois.iis.nu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.nu/nu/Found", response.TemplateName);

            Assert.AreEqual("google.nu", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 05, 06, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 06, 07, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 06, 07, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("mmr-142621", response.Registrant.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(13, response.FieldsParsed);
        }
    }
}
