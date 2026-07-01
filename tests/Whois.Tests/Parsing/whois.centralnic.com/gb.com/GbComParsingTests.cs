using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.GbCom
{
    [TestFixture]
    public class GbComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "gb.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "gb.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("hotel.gb.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO403461", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Wind Internethaus GMBH", response.Registrar.Name);
            Assert.AreEqual("+49.77214070740", response.Registrar.AbuseTelephoneNumber);
            Assert.AreEqual("www.windinternethaus.de", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2014, 2, 12, 9, 45, 17, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 4, 23, 6, 26, 11, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 4, 23, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1049605", response.Registrant.RegistryId);
            Assert.AreEqual("Robert Ragge, Hotel Reservation Service Robert Ragge GmbH", response.Registrant.Name);

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
            Assert.AreEqual("H393781", response.AdminContact.RegistryId);
            Assert.AreEqual("Robert Ragge", response.AdminContact.Name);
            Assert.AreEqual("Hotel Reservation Service Robert Ragge GmbH", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Blaubach 32", response.AdminContact.Address[0]);
            Assert.AreEqual("Koeln", response.AdminContact.Address[1]);
            Assert.AreEqual("NRW", response.AdminContact.Address[2]);
            Assert.AreEqual("50676", response.AdminContact.Address[3]);
            Assert.AreEqual("DE", response.AdminContact.Address[4]);

            Assert.AreEqual("+49.2212077222", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domains@hrs.de", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("H1103064", response.BillingContact.RegistryId);
            Assert.AreEqual("Uwe Watzek, Wind Internethaus GMBH", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Am Krebsgraben 15", response.BillingContact.Address[0]);
            Assert.AreEqual("Villingen-Schwenningen", response.BillingContact.Address[1]);
            Assert.AreEqual("Baden-Wuerttemberg", response.BillingContact.Address[2]);
            Assert.AreEqual("78048", response.BillingContact.Address[3]);
            Assert.AreEqual("DE", response.BillingContact.Address[4]);

            Assert.AreEqual("+49.77214070740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+49.77214070741", response.BillingContact.FaxNumber);
            Assert.AreEqual("info@windinternethaus.de", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("H1103064", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Uwe Watzek, Wind Internethaus GMBH", response.TechnicalContact.Name);

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
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(53, response.FieldsParsed);
        }
    }
}
