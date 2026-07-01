using NUnit.Framework;
using System;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Verisign.Grs.Com.Com
{
    [TestFixture]
    public class ComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("y.com", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 12, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1993, 12, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 12, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[2]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "pending_delete.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.PendingDelete, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("killianestates.com", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("GODADDY.COM, LLC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 05, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 05, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 05, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns75.domaincontrol.com", response.NameServers[0]);
            Assert.AreEqual("ns76.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("pendingDelete", response.DomainStatus[0]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "not_found.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound07", response.TemplateName);

            Assert.AreEqual("u34jedzcq.com", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(23, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found02", response.TemplateName);

            Assert.AreEqual("google.com", response.DomainName.ToString());
            Assert.AreEqual("2138514_DOMAIN_COM-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2011, 7, 20, 16, 55, 31), response.Updated);
            Assert.AreEqual(new DateTime(1997, 9, 15, 4, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2020, 9, 14, 4, 0, 0), response.Expiration);

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
        }
    }
}
