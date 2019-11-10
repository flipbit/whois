using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domain.Registry.Nl.Nl
{
    [TestFixture]
    public class NlParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "found.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Found2", response.TemplateName);

            Assert.AreEqual("tntpost.nl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Transip BV", response.Registrar.Name);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.tntpost.nl", response.NameServers[0]);
            Assert.AreEqual("ns2.tntpost.nl", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual(6, response.FieldsParsed);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "not_assigned.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAssigned, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Found2", response.TemplateName);

            Assert.AreEqual("smsexdates.nl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("JK Websolutions", response.Registrar.Name);

            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns1.jkwebsolutions.nl", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("inactive", response.DomainStatus[0]);

            Assert.AreEqual("no", response.DnsSecStatus);
            Assert.AreEqual(6, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "throttled.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Throttled1", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled_response_throttled_daily()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "throttled_response_throttled_daily.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Throttled2", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_unavailable()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "unavailable.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unavailable, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Unavailable", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "not_found.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.nl", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_quarantined()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "redemption.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Quarantined, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Found2", response.TemplateName);

            Assert.AreEqual("martijn-webdesign.nl", response.DomainName.ToString());


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("in quarantine", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "found_status_registered.txt");
            var response = parser.Parse("whois.domain-registry.nl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domain-registry.nl/nl/Found1", response.TemplateName);

            Assert.AreEqual("google.nl", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor International LTD", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 02, 11, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 05, 27, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("GOO001748-MARKM", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Amphitheatre Parkway 1600", response.Registrant.Address[0]);
            Assert.AreEqual("94043", response.Registrant.Address[1]);
            Assert.AreEqual("MOUNTAIN VIEW CA", response.Registrant.Address[2]);
            Assert.AreEqual("United States of America", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("GOO007083-MARKM", response.AdminContact.RegistryId);
            Assert.AreEqual("GI Google Inc.", response.AdminContact.Name);
            Assert.AreEqual("+1 (0)6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("JOH004771-MARKM", response.TechnicalContact.RegistryId);
            Assert.AreEqual("M Serlin", response.TechnicalContact.Name);
            Assert.AreEqual("+1 (0)2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("active", response.DomainStatus[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }
    }
}
