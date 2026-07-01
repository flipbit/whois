using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iis.Se.Se
{
    [TestFixture]
    public class SeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.iis.se", "se", "found.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("populiscreate.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("EuroDNS S.A", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 08, 05, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 08, 05, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("eds1008-4130626", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("eds0903-00001", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("eds0903-00001", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("eds0903-00002", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.eurodns.com", response.NameServers[0]);
            Assert.AreEqual("ns1.eurodns.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_single()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_nameservers_single.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("nhv.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("SE Direkt", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 03, 18, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1992, 11, 05, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 12, 31, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("nordis0702-00149", response.Registrant.RegistryId);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(10, response.FieldsParsed);
        }

        [Test]
        public void Test_found_nameservers_with_ip()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_nameservers_with_ip.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("loopia.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Loopia AB", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 02, 15, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 09, 15, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 09, 15, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("looloo8804-00001", response.Registrant.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns2.loopia.se", response.NameServers[0]);
            Assert.AreEqual("ns4.loopia.se", response.NameServers[1]);
            Assert.AreEqual("ns3.loopia.se", response.NameServers[2]);
            Assert.AreEqual("ns1.loopia.se", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "not_assigned.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAssigned, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("example.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("CoreRegistry", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2000, 11, 01, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2006, 04, 18, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("system", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(7, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "not_found.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.se", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_status_ok.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("google.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 08, 01, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 10, 20, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 10, 20, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("googoo5855-00001", response.Registrant.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_serverhold()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "other_status_serverhold.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Deactivated, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("ogogle.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Frobbit AB", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 02, 20, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 06, 14, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 06, 14, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("magnus4427-00001", response.Registrant.RegistryId);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.binero.se", response.NameServers[0]);
            Assert.AreEqual("ns2.binero.se", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("deactivated", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(11, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "not_found_status_available.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.se", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.iis.se", "se", "found_status_registered.txt");
            var response = parser.Parse("whois.iis.se", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iis.se/se/Found", response.TemplateName);

            Assert.AreEqual("google.se", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 09, 18, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 10, 20, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 20, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("mmr8008-53808", response.Registrant.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual("unsigned delegation", response.DnsSecStatus);
            Assert.AreEqual(13, response.FieldsParsed);
        }
    }
}
