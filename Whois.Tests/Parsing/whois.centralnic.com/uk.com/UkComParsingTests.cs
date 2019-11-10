using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UkCom
{
    [TestFixture]
    public class UkComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "uk.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "uk.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("history.uk.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO86293", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("E-VELOCITY LTD", response.Registrar.Name);
            Assert.AreEqual("http://www.e-velocity.co.uk/", response.Registrar.Url);
            Assert.AreEqual("01273 684969", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 9, 3, 10, 36, 47, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 8, 31, 11, 50, 57, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 8, 31, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1045821", response.Registrant.RegistryId);
            Assert.AreEqual("Mr. Ray Hatley", response.Registrant.Name);
            Assert.AreEqual("+44.1584873633", response.Registrant.TelephoneNumber);
            Assert.AreEqual("ray@hatley.co.uk", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Tallow House", response.Registrant.Address[0]);
            Assert.AreEqual("65-66 Lower Galdeford", response.Registrant.Address[1]);
            Assert.AreEqual("Ludlow", response.Registrant.Address[2]);
            Assert.AreEqual("Shropshire", response.Registrant.Address[3]);
            Assert.AreEqual("SY8 1RU", response.Registrant.Address[4]);
            Assert.AreEqual("GB", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("H305798", response.AdminContact.RegistryId);
            Assert.AreEqual("Mr. Ray Hatley", response.AdminContact.Name);
            Assert.AreEqual("+44.1584873633", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("ray@hatley.co.uk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("Tallow House", response.AdminContact.Address[0]);
            Assert.AreEqual("65-66 Lower Galdeford", response.AdminContact.Address[1]);
            Assert.AreEqual("Ludlow", response.AdminContact.Address[2]);
            Assert.AreEqual("Shropshire", response.AdminContact.Address[3]);
            Assert.AreEqual("SY8 1RU", response.AdminContact.Address[4]);
            Assert.AreEqual("GB", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("H78362", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Mr Simon Williams", response.TechnicalContact.Name);
            Assert.AreEqual("E-VELOCITY LTD", response.TechnicalContact.Organization);
            Assert.AreEqual("+44.1273684969", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("simon@e-velocity.co.uk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("P.O Box 3295", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Brighton", response.TechnicalContact.Address[1]);
            Assert.AreEqual("BN50 9EY", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns37.eukdns.com", response.NameServers[0]);
            Assert.AreEqual("ns38.eukdns.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(42, response.FieldsParsed);
        }
    }
}
