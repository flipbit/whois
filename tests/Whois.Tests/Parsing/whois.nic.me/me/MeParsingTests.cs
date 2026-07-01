using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Me.Me
{
    [TestFixture]
    public class MeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.me", "me", "found.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("wossna.me", response.DomainName.ToString());
            Assert.AreEqual("D82062-ME", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Gandi SAS R114-ME (81)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 08, 16, 02, 15, 52, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 07, 17, 15, 54, 20, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 07, 17, 15, 54, 20, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GM937-GANDI", response.Registrant.RegistryId);
            Assert.AreEqual("Graeme Mathieson", response.Registrant.Name);
            Assert.AreEqual("+44.7949077744", response.Registrant.TelephoneNumber);
            Assert.AreEqual("mathie@rubaidh.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("12d Monktonhall Terrace", response.Registrant.Address[0]);
            Assert.AreEqual("Musselburgh", response.Registrant.Address[1]);
            Assert.AreEqual("EH21 6ER", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("GM2519-GANDI", response.AdminContact.RegistryId);
            Assert.AreEqual("Graeme Mathieson", response.AdminContact.Name);
            Assert.AreEqual("Rubaidh Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+44.1312735271", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("support@rubaidh.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Stuart House", response.AdminContact.Address[0]);
            Assert.AreEqual("Eskmills", response.AdminContact.Address[1]);
            Assert.AreEqual("Musselburgh", response.AdminContact.Address[2]);
            Assert.AreEqual("EH21 7PB", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("GM2519-GANDI", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Graeme Mathieson", response.TechnicalContact.Name);
            Assert.AreEqual("Rubaidh Ltd", response.TechnicalContact.Organization);
            Assert.AreEqual("+44.1312735271", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("support@rubaidh.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Stuart House", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Eskmills", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Musselburgh", response.TechnicalContact.Address[2]);
            Assert.AreEqual("EH21 7PB", response.TechnicalContact.Address[3]);


            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("INACTIVE", response.DomainStatus[1]);
            Assert.AreEqual("PENDING DELETE", response.DomainStatus[2]);

            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_found_updated_on_is_blank()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "found_updated_on_is_blank.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("factoryoutlet.me", response.DomainName.ToString());
            Assert.AreEqual("D2021453-ME", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Register.it S.p.A. R51-ME", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2011, 05, 27, 16, 22, 58, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 05, 27, 16, 22, 58, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("a66932b07c2b", response.Registrant.RegistryId);
            Assert.AreEqual("Attana' Simone", response.Registrant.Name);
            Assert.AreEqual("+39.0295780392", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+39.0295780392", response.Registrant.FaxNumber);
            Assert.AreEqual("amministrazione@simoneattana.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("via Merano 9/11", response.Registrant.Address[0]);
            Assert.AreEqual("Gessate", response.Registrant.Address[1]);
            Assert.AreEqual("MI", response.Registrant.Address[2]);
            Assert.AreEqual("20060", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("a6ea540dd5aa", response.AdminContact.RegistryId);
            Assert.AreEqual("Attana' Simone", response.AdminContact.Name);
            Assert.AreEqual("Simone Attana'", response.AdminContact.Organization);
            Assert.AreEqual("+39.0295780392", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+39.0295780392", response.AdminContact.FaxNumber);
            Assert.AreEqual("amministrazione@simoneattana.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("via Merano 9/11", response.AdminContact.Address[0]);
            Assert.AreEqual("Gessate", response.AdminContact.Address[1]);
            Assert.AreEqual("MI", response.AdminContact.Address[2]);
            Assert.AreEqual("20060", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("FR-11b2b6d2f885", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Technical support", response.TechnicalContact.Name);
            Assert.AreEqual("REGISTER.IT S.p.a.", response.TechnicalContact.Organization);
            Assert.AreEqual("+39.0353230300", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+39.0353230312", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("support@register.it", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Via Ponti, 6", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Bergamo", response.TechnicalContact.Address[1]);
            Assert.AreEqual("BG", response.TechnicalContact.Address[2]);
            Assert.AreEqual("24126", response.TechnicalContact.Address[3]);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("TRANSFER PROHIBITED", response.DomainStatus[0]);

            Assert.AreEqual(36, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "not_found.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(1, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.me", response.DomainName.ToString());
            Assert.AreEqual("D11599-ME", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc R45-ME", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 05, 12, 09, 21, 14, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 06, 13, 17, 17, 40, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 13, 17, 17, 40, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("mmr-32097", response.Registrant.RegistryId);
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6506234000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dotme@markmonitor.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("mmr-32097", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6506234000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dotme@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("mmr-32097", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6506234000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dotme@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);


            // Domain Status
            Assert.AreEqual(6, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("DELETE PROHIBITED", response.DomainStatus[3]);
            Assert.AreEqual("TRANSFER PROHIBITED", response.DomainStatus[4]);
            Assert.AreEqual("UPDATE PROHIBITED", response.DomainStatus[5]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(47, response.FieldsParsed);
        }
    }
}
