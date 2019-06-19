using NUnit.Framework;
using System;
using Whois.Models;
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
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_pending_delete()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "pending_delete.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.PendingDelete, response.Status);

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "not_found.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found_status_registered.txt");
            var response = parser.Parse("whois.verisign-grs.com", "com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(22, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.verisign-grs.com/com/Redirect", response.TemplateName);

            Assert.AreEqual("google.com", response.DomainName);
            Assert.AreEqual("2138514_DOMAIN_COM-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServerUrl);
            Assert.AreEqual("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2011, 7, 20, 17, 55, 31), response.Updated);
            Assert.AreEqual(new DateTime(1997, 9, 15, 5, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2020, 9, 14, 5, 0, 0), response.Expiration);

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
