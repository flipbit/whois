using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Verisign.Grs.Com.Net
{
    [TestFixture]
    public class NetParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.verisign-grs.com", "net", "not_found.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound07", response.TemplateName);

            Assert.AreEqual("u34jedzcq.net", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "net", "found.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("google.net", response.DomainName.ToString());
            Assert.AreEqual("4802712_DOMAIN_NET-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("292", response.Registrar.IanaId);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2017, 02, 11, 10, 56, 37, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 03, 15, 05, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 03, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(6, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[3]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[4]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[5]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(23, response.FieldsParsed);
        }
    }
}
