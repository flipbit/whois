using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.NeJp
{
    [TestFixture]
    public class NeJpParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("u-tokyo.ac.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 04, 01, 01, 35, 47, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.AreEqual("University of Tokyo", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("MN010JP", response.AdminContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("MN010JP", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("dns1.nc.u-tokyo.ac.jp", response.NameServers[0]);
            Assert.AreEqual("dns2.nc.u-tokyo.ac.jp", response.NameServers[1]);
            Assert.AreEqual("dns3.nc.u-tokyo.ac.jp", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Connected", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("ne.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2005, 03, 30, 17, 37, 52, 000, DateTimeKind.Utc), response.Updated);

            // Nameservers
            Assert.AreEqual(7, response.NameServers.Count);
            Assert.AreEqual("a.dns.jp", response.NameServers[0]);
            Assert.AreEqual("b.dns.jp", response.NameServers[1]);
            Assert.AreEqual("c.dns.jp", response.NameServers[2]);
            Assert.AreEqual("d.dns.jp", response.NameServers[3]);
            Assert.AreEqual("e.dns.jp", response.NameServers[4]);
            Assert.AreEqual("f.dns.jp", response.NameServers[5]);
            Assert.AreEqual("g.dns.jp", response.NameServers[6]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Reserved", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "not_found.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found_status_registered.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("google.ne.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 10, 23, 19, 22, 08, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // AdminContact Details
            Assert.AreEqual("HR058JP", response.AdminContact.RegistryId);

             // TechnicalContact Details
            Assert.AreEqual("TW38378JP", response.TechnicalContact.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Connected", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved_status_reserved()
        {
            var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved_status_reserved.txt");
            var response = parser.Parse("whois.jprs.jp", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.jprs.jp/Found01", response.TemplateName);

            Assert.AreEqual("ne.jp", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2005, 03, 30, 17, 37, 52, 000, DateTimeKind.Utc), response.Updated);

            // Nameservers
            Assert.AreEqual(7, response.NameServers.Count);
            Assert.AreEqual("a.dns.jp", response.NameServers[0]);
            Assert.AreEqual("b.dns.jp", response.NameServers[1]);
            Assert.AreEqual("c.dns.jp", response.NameServers[2]);
            Assert.AreEqual("d.dns.jp", response.NameServers[3]);
            Assert.AreEqual("e.dns.jp", response.NameServers[4]);
            Assert.AreEqual("f.dns.jp", response.NameServers[5]);
            Assert.AreEqual("g.dns.jp", response.NameServers[6]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Reserved", response.DomainStatus[0]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
