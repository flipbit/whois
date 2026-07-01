using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Fi.Fi
{
    [TestFixture]
    public class FiParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_other_status_graceperiod()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "other_status_graceperiod.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Other, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.fi/fi/Found", response.TemplateName);

            Assert.AreEqual("oogle.fi", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 06, 22, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 06, 21, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 06, 21, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Minna", response.Registrant.Name);
            Assert.AreEqual("NURMI", response.Registrant.Organization);
            Assert.AreEqual("+358201599789", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("-", response.Registrant.Address[0]);
            Assert.AreEqual("Huovitie 3", response.Registrant.Address[1]);
            Assert.AreEqual("00400", response.Registrant.Address[2]);
            Assert.AreEqual("HELSINKI", response.Registrant.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("a.ns.netim.net", response.NameServers[0]);
            Assert.AreEqual("b.ns.netim.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Grace Period", response.DomainStatus[0]);

            Assert.AreEqual("no", response.DnsSecStatus);
            Assert.AreEqual(16, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "not_found.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound003", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "found.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.fi/fi/Found", response.TemplateName);

            Assert.AreEqual("google.fi", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 06, 07, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 06, 30, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 07, 04, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Finland Oy", response.Registrant.Name);
            Assert.AreEqual("09073468", response.Registrant.Organization);
            Assert.AreEqual("35896966890", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Domain Administrator", response.Registrant.Address[0]);
            Assert.AreEqual("Mannerheimintie 12 B", response.Registrant.Address[1]);
            Assert.AreEqual("00100", response.Registrant.Address[2]);
            Assert.AreEqual("HELSINKI", response.Registrant.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Granted", response.DomainStatus[0]);

            Assert.AreEqual("no", response.DnsSecStatus);
            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.fi", "fi", "reserved.txt");
            var response = parser.Parse("whois.fi", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.fi/fi/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }
    }
}
