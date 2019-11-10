using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tznic.Or.Tz.Tz
{
    [TestFixture]
    public class TzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_expired()
        {
            var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "expired.txt");
            var response = parser.Parse("whois.tznic.or.tz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Expired, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tznic.or.tz/tz/Found", response.TemplateName);

            Assert.AreEqual("amanabank.co.tz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("REG-XTREME", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 04, 24, 18, 53, 54, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 04, 28, 19, 27, 26, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 04, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("AB2-EXTREME", response.Registrant.RegistryId);
            Assert.AreEqual("Abdul Bandawe", response.Registrant.Name);
            Assert.AreEqual("Amana Bank Ltd", response.Registrant.Organization);
            Assert.AreEqual("+255.713509199", response.Registrant.TelephoneNumber);
            Assert.AreEqual("abdul.bandawe@amanabank.co.tz", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("3rd Floor, PPF Tower", response.Registrant.Address[0]);
            Assert.AreEqual("P. O. Box 9771", response.Registrant.Address[1]);
            Assert.AreEqual("Dar es Salaam", response.Registrant.Address[2]);
            Assert.AreEqual("9771", response.Registrant.Address[3]);
            Assert.AreEqual("TZ", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("AB2-EXTREME", response.AdminContact.RegistryId);
            Assert.AreEqual("Abdul Bandawe", response.AdminContact.Name);
            Assert.AreEqual("Amana Bank Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+255.713509199", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("abdul.bandawe@amanabank.co.tz", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("3rd Floor, PPF Tower", response.AdminContact.Address[0]);
            Assert.AreEqual("P. O. Box 9771", response.AdminContact.Address[1]);
            Assert.AreEqual("Dar es Salaam", response.AdminContact.Address[2]);
            Assert.AreEqual("9771", response.AdminContact.Address[3]);
            Assert.AreEqual("TZ", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("MS1-TZNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Mohsin Sumar", response.TechnicalContact.Name);
            Assert.AreEqual("Extreme Web Technologies", response.TechnicalContact.Organization);
            Assert.AreEqual("+255.784870811", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@extremewebtechnologies.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("5th Floor, Osman Towers", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Zanaki Street", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Dar es Salaam", response.TechnicalContact.Address[2]);
            Assert.AreEqual("P.O.Box 14001", response.TechnicalContact.Address[3]);
            Assert.AreEqual("TZ", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns5.e-xtremetech.net", response.NameServers[0]);
            Assert.AreEqual("ns6.e-xtremetech.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Expired", response.DomainStatus[0]);

            Assert.AreEqual(32, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "not_found.txt");
            var response = parser.Parse("whois.tznic.or.tz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tznic.or.tz/tz/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tznic.or.tz", "tz", "found.txt");
            var response = parser.Parse("whois.tznic.or.tz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.tznic.or.tz/tz/Found", response.TemplateName);

            Assert.AreEqual("dailynews.co.tz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("REG-TZNIC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 08, 30, 15, 47, 56, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 07, 27, 11, 01, 10, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 07, 27, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("CM7-TZNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Collins Mtita", response.Registrant.Name);
            Assert.AreEqual("TSN", response.Registrant.Organization);
            Assert.AreEqual("mcollins@dailynews.co.tz", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Dar_es_salaam", response.Registrant.Address[0]);
            Assert.AreEqual("Dar_es_salaam", response.Registrant.Address[1]);
            Assert.AreEqual("P.O.BOX 9033", response.Registrant.Address[2]);
            Assert.AreEqual("TZ", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("CM7-TZNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("Collins Mtita", response.AdminContact.Name);
            Assert.AreEqual("TSN", response.AdminContact.Organization);
            Assert.AreEqual("mcollins@dailynews.co.tz", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Dar_es_salaam", response.AdminContact.Address[0]);
            Assert.AreEqual("Dar_es_salaam", response.AdminContact.Address[1]);
            Assert.AreEqual("P.O.BOX 9033", response.AdminContact.Address[2]);
            Assert.AreEqual("TZ", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("JN1-TZNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Jacob Noel", response.TechnicalContact.Name);
            Assert.AreEqual("Twiga Hosting", response.TechnicalContact.Organization);
            Assert.AreEqual("+255.755763951", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("jacobn@twigaonline.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Dar es Salaam", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Dar es Salaam", response.TechnicalContact.Address[1]);
            Assert.AreEqual("P.O.Box", response.TechnicalContact.Address[2]);
            Assert.AreEqual("TZ", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.twigaservers.com", response.NameServers[0]);
            Assert.AreEqual("ns2.twigaservers.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("paid and in zone", response.DomainStatus[0]);

            Assert.AreEqual(29, response.FieldsParsed);
        }
    }
}
