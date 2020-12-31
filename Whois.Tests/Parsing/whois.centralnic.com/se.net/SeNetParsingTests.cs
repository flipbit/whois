using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.SeNet
{
    [TestFixture]
    public class SeNetParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "se.net", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "se.net", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("hotel.se.net", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO1617446", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Soluciones Corporativas IP, S.L.U.", response.Registrar.Name);
            Assert.AreEqual("1383", response.Registrar.IanaId);
            Assert.AreEqual("+34.871986600", response.Registrar.AbuseTelephoneNumber);
            Assert.AreEqual("www.scip.es", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 11, 28, 11, 49, 39, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 11, 13, 10, 35, 3, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 11, 13, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("scipr000323588", response.Registrant.RegistryId);
            Assert.AreEqual("Christoph Donath", response.Registrant.Name);
            Assert.AreEqual("Christoph Donath", response.Registrant.Organization);
            Assert.AreEqual("+34.667889082", response.Registrant.TelephoneNumber);
            Assert.AreEqual("info@christophdonath.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("C. Tijarafe 24, 2c", response.Registrant.Address[0]);
            Assert.AreEqual("Cruce de Arinaga", response.Registrant.Address[1]);
            Assert.AreEqual("Palmas (Las)", response.Registrant.Address[2]);
            Assert.AreEqual("35118", response.Registrant.Address[3]);
            Assert.AreEqual("ES", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("scipa000323588", response.AdminContact.RegistryId);
            Assert.AreEqual("Christoph Donath", response.AdminContact.Name);
            Assert.AreEqual("Christoph Donath", response.AdminContact.Organization);
            Assert.AreEqual("+34.667889082", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("info@christophdonath.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("C. Tijarafe 24, 2c", response.AdminContact.Address[0]);
            Assert.AreEqual("Cruce de Arinaga", response.AdminContact.Address[1]);
            Assert.AreEqual("Palmas (Las)", response.AdminContact.Address[2]);
            Assert.AreEqual("35118", response.AdminContact.Address[3]);
            Assert.AreEqual("ES", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("scipb000323588", response.BillingContact.RegistryId);
            Assert.AreEqual("Christoph Donath", response.BillingContact.Name);
            Assert.AreEqual("Christoph Donath", response.BillingContact.Organization);
            Assert.AreEqual("+34.667889082", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("info@christophdonath.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("C. Tijarafe 24, 2c", response.BillingContact.Address[0]);
            Assert.AreEqual("Cruce de Arinaga", response.BillingContact.Address[1]);
            Assert.AreEqual("Palmas (Las)", response.BillingContact.Address[2]);
            Assert.AreEqual("35118", response.BillingContact.Address[3]);
            Assert.AreEqual("ES", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("scipt000323588", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Christoph Donath", response.TechnicalContact.Name);
            Assert.AreEqual("Christoph Donath", response.TechnicalContact.Organization);
            Assert.AreEqual("+34.667889082", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("info@christophdonath.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("C. Tijarafe 24, 2c", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Cruce de Arinaga", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Palmas (Las)", response.TechnicalContact.Address[2]);
            Assert.AreEqual("35118", response.TechnicalContact.Address[3]);
            Assert.AreEqual("ES", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns8261.hostgator.com", response.NameServers[0]);
            Assert.AreEqual("ns8262.hostgator.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(54, response.FieldsParsed);
        }
    }
}
