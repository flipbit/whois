using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Pl.Pl
{
    [TestFixture]
    public class PlParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pl/pl/Found", response.TemplateName);

            Assert.AreEqual("nom.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NASK", response.Registrar.Name);
            Assert.AreEqual("info@dns.pl", response.Registrar.AbuseEmail);
            Assert.AreEqual("+48.22 3808300", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2004, 2, 9, 12, 24, 22), response.Updated);
            Assert.AreEqual(new DateTime(2003, 3, 25, 12, 0, 0), response.Registered);

            // Nameservers
            Assert.AreEqual(7, response.NameServers.Count);
            Assert.AreEqual("f-dns.pl", response.NameServers[0]);
            Assert.AreEqual("i-dns.pl", response.NameServers[1]);
            Assert.AreEqual("a-dns.pl", response.NameServers[2]);
            Assert.AreEqual("e-dns.pl", response.NameServers[3]);
            Assert.AreEqual("d-dns.pl", response.NameServers[4]);
            Assert.AreEqual("h-dns.pl", response.NameServers[5]);
            Assert.AreEqual("g-dns.pl", response.NameServers[6]);

            Assert.AreEqual("Signed", response.DnsSecStatus);
            Assert.AreEqual(15, response.FieldsParsed);        
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pl/pl/Found", response.TemplateName);

            Assert.AreEqual("pentex.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("OVH SAS", response.Registrar.Name);
            Assert.AreEqual("pomoc@ovh.pl", response.Registrar.AbuseEmail);
            Assert.AreEqual("+48.71 7860700", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 6, 19, 15, 56, 18), response.Updated);
            Assert.AreEqual(new DateTime(2001, 6, 20, 13, 0, 0), response.Registered);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("dns1.pentex.pl", response.NameServers[0]);
            Assert.AreEqual("dns2.pentex.pl", response.NameServers[1]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "throttled.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pl/pl/Throttled", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);        
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "not_found.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pl/pl/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.pl", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pl/pl/Found", response.TemplateName);

            Assert.AreEqual("google.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Markmonitor, Inc.", response.Registrar.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 8, 17, 11, 21, 9), response.Updated);
            Assert.AreEqual(new DateTime(2002, 9, 19, 13, 0, 0), response.Registered);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com.", response.NameServers[0]);
            Assert.AreEqual("ns1.google.com.", response.NameServers[1]);

            Assert.AreEqual(9, response.FieldsParsed);
        }

        [Test]
        public void Test_found_08_pl()
        {
            var sample = SampleReader.Read("whois.dns.pl", "pl", "08.pl.txt");

            var response = parser.Parse("whois.dns.pl", sample);

            Assert.AreEqual("08.pl", response.DomainName.ToString());

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.pl/pl/Found", response.TemplateName);

            Assert.AreEqual("08.pl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("OVH SAS", response.Registrar.Name);
            Assert.AreEqual("+48.717500200", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2019, 2, 1, 18, 5, 52), response.Updated);
            Assert.AreEqual(new DateTime(2004, 2, 7, 6, 45, 12), response.Registered);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("dns111.ovh.net.", response.NameServers[0]);
            Assert.AreEqual("ns111.ovh.net.", response.NameServers[1]);

            Assert.AreEqual(8, response.FieldsParsed);
        }
    }
}
