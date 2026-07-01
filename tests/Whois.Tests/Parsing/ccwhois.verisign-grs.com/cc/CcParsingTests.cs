using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Ccwhois.Verisign.Grs.Com.Cc
{
    [TestFixture]
    public class CcParsingTests : ParsingTests
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
            var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "found.txt");
            var response = parser.Parse("ccwhois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual("m4r0c-s3curity.cc", response.DomainName.ToString());

            Assert.AreEqual("TUCOWS INC.", response.Registrar.Name);
            Assert.AreEqual("http://domainhelp.opensrs.net", response.Registrar.Url);
            Assert.AreEqual("whois.tucows.com", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2010, 5, 7, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2009, 3, 26, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2011, 3, 26, 0, 0, 0), response.Expiration);

            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT-XFER-PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT-UPDATE-PROHIBITED", response.DomainStatus[1]);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "not_found.txt");
            var response = parser.Parse("ccwhois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
            Assert.AreEqual("u34jedzcq.cc", response.DomainName.ToString());
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "found_status_registered.txt");
            var response = parser.Parse("ccwhois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual("google.cc", response.DomainName.ToString());
            Assert.AreEqual("86420657_DOMAIN_CC-VRSN", response.RegistryDomainId);

            Assert.AreEqual("MARKMONITOR INC.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2017, 5, 6, 9, 28, 40, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 6, 7, 4, 0, 0, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 6, 7, 4, 0, 0, DateTimeKind.Utc), response.Expiration);

            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

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
