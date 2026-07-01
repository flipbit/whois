using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cz.Cz
{
    [TestFixture]
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
            var response = parser.Parse("whois.nic.cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("rybarskepotreby-marek.cz", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 01, 04, 18, 57, 14, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 12, 31, 03, 39, 20, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("A24CONTACT-42407", response.Registrant.RegistryId);
            Assert.AreEqual("Leoš Marek", response.Registrant.Name);
            Assert.AreEqual("Leoš Marek", response.Registrant.Organization);
            Assert.AreEqual(new DateTime(2010, 12, 31, 03, 36, 50, 000, DateTimeKind.Utc), response.Registrant.Created);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Krásný Dvůr 180", response.Registrant.Address[0]);
            Assert.AreEqual("Krásný Dvůr", response.Registrant.Address[1]);
            Assert.AreEqual("43972", response.Registrant.Address[2]);
            Assert.AreEqual("CZ", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("WEBAREAL-CZ", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Jaroslav Hansal", response.TechnicalContact.Name);
            Assert.AreEqual("info@webareal.cz", response.TechnicalContact.Email);
            Assert.AreEqual(new DateTime(2009, 04, 10, 14, 48, 02, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Rudolfovská tř. 247/85", response.TechnicalContact.Address[0]);
            Assert.AreEqual("České Budějovice", response.TechnicalContact.Address[1]);
            Assert.AreEqual("37001", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CZ", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.unihost.cz", response.NameServers[0]);
            Assert.AreEqual("ns2.unihost.cz", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("paid and in zone", response.DomainStatus[0]);

            Assert.AreEqual(27, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "throttled.txt");
            var response = parser.Parse("whois.nic.cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Throttled", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_response_with_keyset()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "found_response_with_keyset.txt");
            var response = parser.Parse("whois.nic.cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("realityporno.cz", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 10, 07, 21, 51, 15, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 01, 30, 18, 55, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 01, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("SB:GLOBE-SPKA040146", response.Registrant.RegistryId);
            Assert.AreEqual("PK62, a.s", response.Registrant.Name);
            Assert.AreEqual("PK62, a.s", response.Registrant.Organization);
            Assert.AreEqual("domeny@pk62.cz", response.Registrant.Email);
            Assert.AreEqual(new DateTime(2004, 11, 19, 15, 05, 00, 000, DateTimeKind.Utc), response.Registrant.Created);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Bohdalecka 6/1420", response.Registrant.Address[0]);
            Assert.AreEqual("Praha 10", response.Registrant.Address[1]);
            Assert.AreEqual("10100", response.Registrant.Address[2]);
            Assert.AreEqual("CZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("GLOBE-PKVO462567", response.AdminContact.RegistryId);
            Assert.AreEqual("Pavel Kvoriak", response.AdminContact.Name);
            Assert.AreEqual("domeny@pk62.cz", response.AdminContact.Email);
            Assert.AreEqual(new DateTime(2004, 11, 19, 14, 05, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Bohdalecka 6/1420", response.AdminContact.Address[0]);
            Assert.AreEqual("Praha 10", response.AdminContact.Address[1]);
            Assert.AreEqual("10100", response.AdminContact.Address[2]);
            Assert.AreEqual("CZ", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("ACTIVE24", response.TechnicalContact.RegistryId);
            Assert.AreEqual("ACTIVE 24, s.r.o.", response.TechnicalContact.Name);
            Assert.AreEqual("ACTIVE 24, s.r.o.", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2008, 04, 29, 12, 35, 02, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Sokolovská 394/17", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Praha 8", response.TechnicalContact.Address[1]);
            Assert.AreEqual("186 00", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CZ", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("beta.ns.active24.cz", response.NameServers[0]);
            Assert.AreEqual("gama.ns.active24.sk", response.NameServers[1]);
            Assert.AreEqual("alfa.ns.active24.cz", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("paid and in zone", response.DomainStatus[0]);

            Assert.AreEqual(42, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "not_found.txt");
            var response = parser.Parse("whois.nic.cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("google.cz", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 05, 18, 23, 28, 45, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2000, 07, 21, 15, 21, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MM12383", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);
            Assert.AreEqual(new DateTime(2011, 05, 18, 23, 28, 26, 000, DateTimeKind.Utc), response.Registrant.Created);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("94043", response.Registrant.Address[2]);
            Assert.AreEqual("CA", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("MM12383", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);
            Assert.AreEqual(new DateTime(2011, 05, 18, 23, 28, 26, 000, DateTimeKind.Utc), response.AdminContact.Created);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("94043", response.AdminContact.Address[2]);
            Assert.AreEqual("CA", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MM193020", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Provisioning", response.TechnicalContact.Name);
            Assert.AreEqual("MarkMonitor, Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);
            Assert.AreEqual(new DateTime(2011, 02, 03, 18, 24, 34, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("10400 Overland Road PMB 155", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise", response.TechnicalContact.Address[1]);
            Assert.AreEqual("83709-1433", response.TechnicalContact.Address[2]);
            Assert.AreEqual("ID", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns2.google.com", response.NameServers[0]);
            Assert.AreEqual("ns4.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns1.google.com", response.NameServers[3]);

            Assert.AreEqual(33, response.FieldsParsed);
        }

        [Test]
        public void Test_found_phoca_cz()
        {
            var sample = SampleReader.Read("whois.nic.cz", "cz", "phoca.cz.txt");
            
            var response = parser.Parse("whois.nic.cz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.cz/cz/Found", response.TemplateName);

            Assert.AreEqual("phoca.cz", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2018, 05, 15, 21, 32, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 08, 08, 07, 15, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2019, 08, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("SB:SUB000029824-ZONER", response.Registrant.RegistryId);
            Assert.AreEqual("Lenka Medunová", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2007, 08, 08, 06, 55, 00, 000, DateTimeKind.Utc), response.Registrant.Created);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Bratrstva 38", response.Registrant.Address[0]);
            Assert.AreEqual("Znojmo", response.Registrant.Address[1]);
            Assert.AreEqual("66902", response.Registrant.Address[2]);
            Assert.AreEqual("CZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("PER000029824-ZONER", response.AdminContact.RegistryId);
            Assert.AreEqual("Lenka Medunová", response.AdminContact.Name);
            Assert.AreEqual(new DateTime(2007, 08, 08, 06, 15, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Bratrstva 38", response.AdminContact.Address[0]);
            Assert.AreEqual("Znojmo", response.AdminContact.Address[1]);
            Assert.AreEqual("66902", response.AdminContact.Address[2]);
            Assert.AreEqual("CZ", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("SB:SUB100000001-ZONER", response.TechnicalContact.RegistryId);
            Assert.AreEqual("ZONER software a.s.", response.TechnicalContact.Name);
            Assert.AreEqual("ZONER software a.s.", response.TechnicalContact.Organization);
            Assert.AreEqual(new DateTime(2001, 08, 10, 22, 13, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Nové sady 18", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Brno", response.TechnicalContact.Address[1]);
            Assert.AreEqual("60200", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CZ", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.videon-znojmo.cz", response.NameServers[0]);
            Assert.AreEqual("ns1.videon-znojmo.cz", response.NameServers[1]);

            Assert.AreEqual(44, response.FieldsParsed);
        }
    }
}
