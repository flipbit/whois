using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.SeCom
{
    [TestFixture]
    public class SeComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "se.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "se.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("hotel.se.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO561053", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("InternetX GmbH", response.Registrar.Name);
            Assert.AreEqual("http://www.internetx.de/", response.Registrar.Url);
            Assert.AreEqual("+49-941-595590", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 6, 3, 10, 33, 46, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 5, 10, 5, 17, 32, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 5, 10, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("INX-10599082com", response.Registrant.RegistryId);
            Assert.AreEqual("Hotel Reservation Service Robert Ragge GmbH", response.Registrant.Name);
            Assert.AreEqual("Hotel Reservation Service Robert Ragge GmbH", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Blaubach 32", response.Registrant.Address[0]);
            Assert.AreEqual("Koeln", response.Registrant.Address[1]);
            Assert.AreEqual("NRW", response.Registrant.Address[2]);
            Assert.AreEqual("50676", response.Registrant.Address[3]);
            Assert.AreEqual("DE", response.Registrant.Address[4]);

            Assert.AreEqual("+49.2212077222", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domains@hrs.de", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("INX-201727com", response.AdminContact.RegistryId);
            Assert.AreEqual("Robert Ragge", response.AdminContact.Name);
            Assert.AreEqual("Hotel Reservation Service Robert Ragge GmbH", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Blaubach 32", response.AdminContact.Address[0]);
            Assert.AreEqual("Koeln", response.AdminContact.Address[1]);
            Assert.AreEqual("DE", response.AdminContact.Address[2]);
            Assert.AreEqual("50676", response.AdminContact.Address[3]);
            Assert.AreEqual("DE", response.AdminContact.Address[4]);

            Assert.AreEqual("+49.2212077222", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domains@hrs.de", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("INX-10599082com", response.BillingContact.RegistryId);
            Assert.AreEqual("Hotel Reservation Service Robert Ragge GmbH", response.BillingContact.Name);
            Assert.AreEqual("Hotel Reservation Service Robert Ragge GmbH", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Blaubach 32", response.BillingContact.Address[0]);
            Assert.AreEqual("Koeln", response.BillingContact.Address[1]);
            Assert.AreEqual("NRW", response.BillingContact.Address[2]);
            Assert.AreEqual("50676", response.BillingContact.Address[3]);
            Assert.AreEqual("DE", response.BillingContact.Address[4]);

            Assert.AreEqual("+49.2212077222", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+49.2212077394", response.BillingContact.FaxNumber);
            Assert.AreEqual("domains@hrs.de", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("INX-201728com", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Uwe Watzek", response.TechnicalContact.Name);
            Assert.AreEqual("Wind Internethaus GmbH", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Am Krebsgraben 15", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Haus 2", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Villingen-Schwenningen", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Baden-Wuerttemberg", response.TechnicalContact.Address[3]);
            Assert.AreEqual("78048", response.TechnicalContact.Address[4]);
            Assert.AreEqual("DE", response.TechnicalContact.Address[5]);

            Assert.AreEqual("+49.77214070740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@windinternethaus.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.hrs.de", response.NameServers[0]);
            Assert.AreEqual("ns2.hrs.de", response.NameServers[1]);
            Assert.AreEqual("ns2.surfbrett.de", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(56, response.FieldsParsed);
        }
    }
}
