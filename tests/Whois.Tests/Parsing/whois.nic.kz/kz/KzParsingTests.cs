using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Kz.Kz
{
    public class KzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public KzParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.kz/kz/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found", "tabu.kz.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.kz/kz/found/01", response.TemplateName);

            Assert.Equal("tabu.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("HOSTER.KZ", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 10, 04, 17, 32, 58, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 10, 04, 17, 24, 09, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Alexey Chumakov", response.Registrant.Name);
            Assert.Equal("Alexey Chumakov", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("UA 13-25-27", response.Registrant.Address[0]);
            Assert.Equal("Tashkent", response.Registrant.Address[1]);
            Assert.Equal("700194", response.Registrant.Address[2]);
            Assert.Equal("UZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("HOSTERKZ-59014", response.AdminContact.RegistryId);
            Assert.Equal("Hostmaster", response.AdminContact.Name);
            Assert.Equal("+7.7212501060", response.AdminContact.TelephoneNumber);
            Assert.Equal("+7.7212501060", response.AdminContact.FaxNumber);
            Assert.Equal("kohaner@gmail.com", response.AdminContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.regi.kz", response.NameServers[0]);
            Assert.Equal("ns2.regi.kz", response.NameServers[1]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientRenewProhibited", response.DomainStatus[1]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);

            Assert.Equal(21, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found", "google.kz.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.kz/kz/found/01", response.TemplateName);

            Assert.Equal("google.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("KAZNIC", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 08, 21, 09, 11, 45, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 06, 07, 20, 01, 43, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("DA141-SL", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506181499", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(20, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_updated_on_blank()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found", "found_updated_on_blank.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.kz/kz/found/01", response.TemplateName);

            Assert.Equal("pedamotor.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("ICPS", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 09, 13, 06, 40, 28, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Tsymbal Eugeniy", response.Registrant.Name);
            Assert.Equal("NUR-LIGHT TOO", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Abay str 5, 1", response.Registrant.Address[0]);
            Assert.Equal("Almaty", response.Registrant.Address[1]);
            Assert.Equal("483331", response.Registrant.Address[2]);
            Assert.Equal("KZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("PS0000001408-KZ", response.AdminContact.RegistryId);
            Assert.Equal("Tsymbal Eugeniy", response.AdminContact.Name);
            Assert.Equal("+7-727-2954585", response.AdminContact.TelephoneNumber);
            Assert.Equal("+7-727-3827662", response.AdminContact.FaxNumber);
            Assert.Equal("eas_kz@mail.ru", response.AdminContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns.ps.kz", response.NameServers[0]);
            Assert.Equal("ns1.ps.kz", response.NameServers[1]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("clientRenewProhibited", response.DomainStatus[1]);

            Assert.Equal(19, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "not-found", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.kz/kz/not-found/01", response.TemplateName);


            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.kz/kz/found/01", response.TemplateName);

            Assert.Equal("google.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("KAZNIC", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 11, 28, 03, 16, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 06, 07, 13, 01, 43, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("C000000197393-KZ", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(20, response.FieldsParsed);
        }
    }
}
