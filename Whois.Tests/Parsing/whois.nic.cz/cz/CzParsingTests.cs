using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cz.Cz
{
    [TestFixture]
    [Ignore("TODO")]
    public class CzParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.cz", "cz", "found.txt");
            var response = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("rybarskepotreby-marek.cz", response.DomainName);

            Assert.AreEqual(new DateTime(2011, 4, 1, 18, 57, 14), response.Updated);
            Assert.AreEqual(new DateTime(2010, 12, 31, 3, 39, 20), response.Registered);
            Assert.AreEqual(new DateTime(2013, 12, 31, 0, 0, 0), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.unihost.cz", response.NameServers[0]);
            Assert.AreEqual("ns2.unihost.cz", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("paid and in zone", response.DomainStatus[0]);

            Assert.AreEqual(8, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "throttled.txt");
            var response = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Throttled", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_response_with_keyset()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "found_response_with_keyset.txt");
            var response = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("realityporno.cz", response.DomainName);

            Assert.AreEqual(new DateTime(2010, 6, 3, 15, 53, 4), response.Updated);
            Assert.AreEqual(new DateTime(2014, 1, 30, 0, 0, 0), response.Expiration);

            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("gama.ns.active24.sk", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("paid and in zone", response.DomainStatus[0]);

            Assert.AreEqual(6, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "not_found.txt");
            var response = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("google.cz", response.DomainName);

            Assert.AreEqual(new DateTime(2014, 7, 22, 0, 0, 0), response.Expiration);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns1.google.com", response.NameServers[3]);

            Assert.AreEqual(7, response.FieldsParsed);
        }

        [Test]
        public void Test_found_phoca_cz()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "phoca.cz.txt");
            
            var response = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("phoca.cz", response.DomainName);

            Assert.AreEqual(new DateTime(2012, 4, 4, 4, 37, 56), response.Updated);
            Assert.AreEqual(new DateTime(2007, 8, 8, 7, 15, 0), response.Registered);
            Assert.AreEqual(new DateTime(2019, 8, 8, 0, 0, 0), response.Expiration);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.videon-znojmo.cz", response.NameServers[0]);
            Assert.AreEqual("ns1.videon-znojmo.cz", response.NameServers[1]);

            Assert.AreEqual(7, response.FieldsParsed);
        }
    }
}
