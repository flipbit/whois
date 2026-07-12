using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Register.Bg.Bg
{
    public class BgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.register.bg", "bg", "found", "found.txt");
            var response = parser.Parse("whois.register.bg", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.register.bg/bg/found/01", response.TemplateName);

            Assert.Equal("orbitel.bg", response.DomainName.ToString());

            Assert.Equal(new DateTime(1997, 11, 23, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 12, 31, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Orbitel S.A.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(2, response.Registrant.Address.Count);
            Assert.Equal("SOFIA, 1505", response.Registrant.Address[0]);
            Assert.Equal("BULGARIA", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.Equal("VF15885", response.AdminContact.RegistryId);
            Assert.Equal("Victor Francess", response.AdminContact.Name);
            Assert.Equal("Orbitel Ltd.", response.AdminContact.Organization);
            Assert.Equal("+359 2 9809077", response.AdminContact.TelephoneNumber);
            Assert.Equal("+359 2 9804258", response.AdminContact.FaxNumber);
            Assert.Equal("registry@orbitel.bg", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("1, Macedonia sq., fl.18, BG-1040 Sofia", response.AdminContact.Address[0]);
            Assert.Equal("SOFIA, 1040", response.AdminContact.Address[1]);
            Assert.Equal("BULGARIA", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("AS50734", response.TechnicalContact.RegistryId);
            Assert.Equal("Andrejana P Shojkova", response.TechnicalContact.Name);
            Assert.Equal("Orbitel S.C.", response.TechnicalContact.Organization);
            Assert.Equal("+359 2 4004731", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+359 2 4004744", response.TechnicalContact.FaxNumber);
            Assert.Equal("registry@orbitel.bg", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("1 Macedonia Sq., KNSB building, floor 18, room 10, 1000 Sofia", response.TechnicalContact.Address[0]);
            Assert.Equal("SOFIA,", response.TechnicalContact.Address[1]);
            Assert.Equal("BULGARIA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("chicken.orbitel.bg", response.NameServers[0]);
            Assert.Equal("ns.orbitel.bg", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered", response.DomainStatus[0]);

            Assert.Equal("Inactive", response.DnsSecStatus);
            Assert.Equal(29, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.register.bg", "bg", "not-found", "not_found.txt");
            var response = parser.Parse("whois.register.bg", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.register.bg/bg/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.bg", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.register.bg", "bg", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.register.bg", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.register.bg/bg/found/01", response.TemplateName);

            Assert.Equal("google.bg", response.DomainName.ToString());

            Assert.Equal(new DateTime(2003, 06, 29, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 06, 29, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphithetre Parkway, Mountain View CA 94043 US", response.Registrant.Address[0]);
            Assert.Equal("N/A, 1000", response.Registrant.Address[1]);
            Assert.Equal("BULGARIA", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("TS18-BGNIC", response.AdminContact.RegistryId);
            Assert.Equal("Todor Stoyanov", response.AdminContact.Name);
            Assert.Equal("Tonisto Patent Agency", response.AdminContact.Organization);
            Assert.Equal("+359 52 630803", response.AdminContact.TelephoneNumber);
            Assert.Equal("+359 52 699014", response.AdminContact.FaxNumber);
            Assert.Equal("tonisto@mbox.digsys.bg", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(2, response.AdminContact.Address.Count);
            Assert.Equal("7 Radko Dimitriev str., Varna", response.AdminContact.Address[0]);
            Assert.Equal("BULGARIA", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.Equal("DNS11-BGNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1 6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1 6506181499", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway, Mountain View CA 94043 US", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("ns4.google.com", response.NameServers[0]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Registered", response.DomainStatus[0]);

            Assert.Equal(25, response.FieldsParsed);
        }
    }
}
