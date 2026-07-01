using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Tvwhois.Verisign.Grs.Com.Tv
{
    [TestFixture]
    public class TvParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "found.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(7, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("set.tv", response.DomainName.ToString());

            Assert.AreEqual(".TV RESERVED DOMAINS", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 3, 18, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2010, 3, 18, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2011, 3, 18, 0, 0, 0), response.Expiration);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("SERVER-XFER-PROHIBITED", response.DomainStatus[0]);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "not_found.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(2, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("u34jedzcq.tv", response.DomainName.ToString());
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("tvwhois.verisign-grs.com", "tv", "found_status_registered.txt");
            var response = parser.Parse("tvwhois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(21, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("google.tv", response.DomainName.ToString());

            Assert.AreEqual("MARKMONITOR INC.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2017, 7, 1, 09, 25, 47, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 8, 2, 16, 43, 36, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 8, 2, 16, 43, 36, DateTimeKind.Utc), response.Expiration);

            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);

            Assert.AreEqual(6, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[3]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[4]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[5]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
        }
    }
}
