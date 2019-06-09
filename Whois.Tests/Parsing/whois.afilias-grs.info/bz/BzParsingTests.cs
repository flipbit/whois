using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Bz
{
    [TestFixture]
    public class BzParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.afilias-grs.info", "bz", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", "bz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "bz", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", "bz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(17, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("google.bz", response.DomainName);
            Assert.AreEqual("D354967-LRCC", response.RegistryDomainId);

            Assert.AreEqual("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("whois.markmonitor.com", response.Registrar.WhoisServerUrl);

            Assert.AreEqual(new DateTime(2014, 1, 11, 10, 18, 14), response.Updated);
            Assert.AreEqual(new DateTime(2006, 2, 12, 18, 8, 52), response.Registered);
            Assert.AreEqual(new DateTime(2015, 2, 12, 18, 8, 52), response.Expiration);

            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("RENEWPERIOD", response.DomainStatus[3]);
        }
    }
}
