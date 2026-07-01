using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Kz.Kz
{
    [TestFixture]
    public class KzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "not_found.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.kz/kz/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.kz/kz/Found", response.TemplateName);

            Assert.AreEqual("tabu.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("HOSTER.KZ", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 10, 04, 17, 32, 58, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 10, 04, 17, 24, 09, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Alexey Chumakov", response.Registrant.Name);
            Assert.AreEqual("Alexey Chumakov", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("UA 13-25-27", response.Registrant.Address[0]);
            Assert.AreEqual("Tashkent", response.Registrant.Address[1]);
            Assert.AreEqual("700194", response.Registrant.Address[2]);
            Assert.AreEqual("UZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("HOSTERKZ-59014", response.AdminContact.RegistryId);
            Assert.AreEqual("Hostmaster", response.AdminContact.Name);
            Assert.AreEqual("+7.7212501060", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+7.7212501060", response.AdminContact.FaxNumber);
            Assert.AreEqual("kohaner@gmail.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.regi.kz", response.NameServers[0]);
            Assert.AreEqual("ns2.regi.kz", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);

            Assert.AreEqual(21, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found_status_ok.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.kz/kz/Found", response.TemplateName);

            Assert.AreEqual("google.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("KAZNIC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 08, 21, 09, 11, 45, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 06, 07, 20, 01, 43, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("DA141-SL", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506181499", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(20, response.FieldsParsed);
        }

        [Test]
        public void Test_found_updated_on_blank()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found_updated_on_blank.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.kz/kz/Found", response.TemplateName);

            Assert.AreEqual("pedamotor.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("ICPS", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 09, 13, 06, 40, 28, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Tsymbal Eugeniy", response.Registrant.Name);
            Assert.AreEqual("NUR-LIGHT TOO", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Abay str 5, 1", response.Registrant.Address[0]);
            Assert.AreEqual("Almaty", response.Registrant.Address[1]);
            Assert.AreEqual("483331", response.Registrant.Address[2]);
            Assert.AreEqual("KZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("PS0000001408-KZ", response.AdminContact.RegistryId);
            Assert.AreEqual("Tsymbal Eugeniy", response.AdminContact.Name);
            Assert.AreEqual("+7-727-2954585", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+7-727-3827662", response.AdminContact.FaxNumber);
            Assert.AreEqual("eas_kz@mail.ru", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.ps.kz", response.NameServers[0]);
            Assert.AreEqual("ns1.ps.kz", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[1]);

            Assert.AreEqual(19, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.kz/kz/NotFound", response.TemplateName);


            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.kz", "kz", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.kz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.kz/kz/Found", response.TemplateName);

            Assert.AreEqual("google.kz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("KAZNIC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 11, 28, 03, 16, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1999, 06, 07, 13, 01, 43, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("C000000197393-KZ", response.AdminContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(20, response.FieldsParsed);
        }
    }
}
