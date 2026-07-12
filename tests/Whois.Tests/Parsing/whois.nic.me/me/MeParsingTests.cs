using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Me.Me
{
    public class MeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public MeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "found", "wossna.me.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("wossna.me", response.DomainName.ToString());
            Assert.Equal("D82062-ME", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Gandi SAS R114-ME (81)", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 08, 16, 02, 15, 52, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 07, 17, 15, 54, 20, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 07, 17, 15, 54, 20, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("GM937-GANDI", response.Registrant.RegistryId);
            Assert.Equal("Graeme Mathieson", response.Registrant.Name);
            Assert.Equal("+44.7949077744", response.Registrant.TelephoneNumber);
            Assert.Equal("mathie@rubaidh.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("12d Monktonhall Terrace", response.Registrant.Address[0]);
            Assert.Equal("Musselburgh", response.Registrant.Address[1]);
            Assert.Equal("EH21 6ER", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("GM2519-GANDI", response.AdminContact.RegistryId);
            Assert.Equal("Graeme Mathieson", response.AdminContact.Name);
            Assert.Equal("Rubaidh Ltd", response.AdminContact.Organization);
            Assert.Equal("+44.1312735271", response.AdminContact.TelephoneNumber);
            Assert.Equal("support@rubaidh.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Stuart House", response.AdminContact.Address[0]);
            Assert.Equal("Eskmills", response.AdminContact.Address[1]);
            Assert.Equal("Musselburgh", response.AdminContact.Address[2]);
            Assert.Equal("EH21 7PB", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("GM2519-GANDI", response.TechnicalContact.RegistryId);
            Assert.Equal("Graeme Mathieson", response.TechnicalContact.Name);
            Assert.Equal("Rubaidh Ltd", response.TechnicalContact.Organization);
            Assert.Equal("+44.1312735271", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("support@rubaidh.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Stuart House", response.TechnicalContact.Address[0]);
            Assert.Equal("Eskmills", response.TechnicalContact.Address[1]);
            Assert.Equal("Musselburgh", response.TechnicalContact.Address[2]);
            Assert.Equal("EH21 7PB", response.TechnicalContact.Address[3]);


            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[0]);
            Assert.Equal("INACTIVE", response.DomainStatus[1]);
            Assert.Equal("PENDING DELETE", response.DomainStatus[2]);

            Assert.Equal(36, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_updated_on_is_blank()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "found", "factoryoutlet.me.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("factoryoutlet.me", response.DomainName.ToString());
            Assert.Equal("D2021453-ME", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Register.it S.p.A. R51-ME", response.Registrar.Name);

            Assert.Equal(new DateTime(2011, 05, 27, 16, 22, 58, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 05, 27, 16, 22, 58, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("a66932b07c2b", response.Registrant.RegistryId);
            Assert.Equal("Attana' Simone", response.Registrant.Name);
            Assert.Equal("+39.0295780392", response.Registrant.TelephoneNumber);
            Assert.Equal("+39.0295780392", response.Registrant.FaxNumber);
            Assert.Equal("amministrazione@simoneattana.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("via Merano 9/11", response.Registrant.Address[0]);
            Assert.Equal("Gessate", response.Registrant.Address[1]);
            Assert.Equal("MI", response.Registrant.Address[2]);
            Assert.Equal("20060", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("a6ea540dd5aa", response.AdminContact.RegistryId);
            Assert.Equal("Attana' Simone", response.AdminContact.Name);
            Assert.Equal("Simone Attana'", response.AdminContact.Organization);
            Assert.Equal("+39.0295780392", response.AdminContact.TelephoneNumber);
            Assert.Equal("+39.0295780392", response.AdminContact.FaxNumber);
            Assert.Equal("amministrazione@simoneattana.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("via Merano 9/11", response.AdminContact.Address[0]);
            Assert.Equal("Gessate", response.AdminContact.Address[1]);
            Assert.Equal("MI", response.AdminContact.Address[2]);
            Assert.Equal("20060", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("FR-11b2b6d2f885", response.TechnicalContact.RegistryId);
            Assert.Equal("Technical support", response.TechnicalContact.Name);
            Assert.Equal("REGISTER.IT S.p.a.", response.TechnicalContact.Organization);
            Assert.Equal("+39.0353230300", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+39.0353230312", response.TechnicalContact.FaxNumber);
            Assert.Equal("support@register.it", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Via Ponti, 6", response.TechnicalContact.Address[0]);
            Assert.Equal("Bergamo", response.TechnicalContact.Address[1]);
            Assert.Equal("BG", response.TechnicalContact.Address[2]);
            Assert.Equal("24126", response.TechnicalContact.Address[3]);


            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("TRANSFER PROHIBITED", response.DomainStatus[0]);

            Assert.Equal(36, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.me", "me", "found", "google.me.txt");
            var response = parser.Parse("whois.nic.me", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(1, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.me", response.DomainName.ToString());
            Assert.Equal("D11599-ME", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor Inc R45-ME", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 05, 12, 09, 21, 14, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 06, 13, 17, 17, 40, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 06, 13, 17, 17, 40, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("mmr-32097", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6506234000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
            Assert.Equal("dotme@markmonitor.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("mmr-32097", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6506234000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dotme@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("mmr-32097", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6506234000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dotme@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("CA", response.TechnicalContact.Address[2]);
            Assert.Equal("94043", response.TechnicalContact.Address[3]);


            // Domain Status
            Assert.Equal(6, response.DomainStatus.Count);
            Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);
            Assert.Equal("DELETE PROHIBITED", response.DomainStatus[3]);
            Assert.Equal("TRANSFER PROHIBITED", response.DomainStatus[4]);
            Assert.Equal("UPDATE PROHIBITED", response.DomainStatus[5]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(48, response.FieldsParsed);
        }
    }
}
