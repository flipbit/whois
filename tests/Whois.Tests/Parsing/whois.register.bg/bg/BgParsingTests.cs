using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Register.Bg.Bg
{
    [TestFixture]
    public class BgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.register.bg", "bg", "found.txt");
            var response = parser.Parse("whois.register.bg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.register.bg/bg/Found", response.TemplateName);

            Assert.AreEqual("orbitel.bg", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(1997, 11, 23, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 12, 31, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Orbitel S.A.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("SOFIA, 1505", response.Registrant.Address[0]);
            Assert.AreEqual("BULGARIA", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("VF15885", response.AdminContact.RegistryId);
            Assert.AreEqual("Victor Francess", response.AdminContact.Name);
            Assert.AreEqual("Orbitel Ltd.", response.AdminContact.Organization);
            Assert.AreEqual("+359 2 9809077", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+359 2 9804258", response.AdminContact.FaxNumber);
            Assert.AreEqual("registry@orbitel.bg", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("1, Macedonia sq., fl.18, BG-1040 Sofia", response.AdminContact.Address[0]);
            Assert.AreEqual("SOFIA, 1040", response.AdminContact.Address[1]);
            Assert.AreEqual("BULGARIA", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("AS50734", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Andrejana P Shojkova", response.TechnicalContact.Name);
            Assert.AreEqual("Orbitel S.C.", response.TechnicalContact.Organization);
            Assert.AreEqual("+359 2 4004731", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+359 2 4004744", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("registry@orbitel.bg", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1 Macedonia Sq., KNSB building, floor 18, room 10, 1000 Sofia", response.TechnicalContact.Address[0]);
            Assert.AreEqual("SOFIA,", response.TechnicalContact.Address[1]);
            Assert.AreEqual("BULGARIA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("chicken.orbitel.bg", response.NameServers[0]);
            Assert.AreEqual("ns.orbitel.bg", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered", response.DomainStatus[0]);

            Assert.AreEqual("Inactive", response.DnsSecStatus);
            Assert.AreEqual(29, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.register.bg", "bg", "not_found.txt");
            var response = parser.Parse("whois.register.bg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.register.bg/bg/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.bg", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.register.bg", "bg", "found_status_registered.txt");
            var response = parser.Parse("whois.register.bg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.register.bg/bg/Found", response.TemplateName);

            Assert.AreEqual("google.bg", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2003, 06, 29, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 29, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphithetre Parkway, Mountain View CA 94043 US", response.Registrant.Address[0]);
            Assert.AreEqual("N/A, 1000", response.Registrant.Address[1]);
            Assert.AreEqual("BULGARIA", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("TS18-BGNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Todor Stoyanov", response.AdminContact.Name);
            Assert.AreEqual("Tonisto Patent Agency", response.AdminContact.Organization);
            Assert.AreEqual("+359 52 630803", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+359 52 699014", response.AdminContact.FaxNumber);
            Assert.AreEqual("tonisto@mbox.digsys.bg", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("7 Radko Dimitriev str., Varna", response.AdminContact.Address[0]);
            Assert.AreEqual("BULGARIA", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("DNS11-BGNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1 6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1 6506181499", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway, Mountain View CA 94043 US", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns4.google.com", response.NameServers[0]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Registered", response.DomainStatus[0]);

            Assert.AreEqual(25, response.FieldsParsed);
        }
    }
}
