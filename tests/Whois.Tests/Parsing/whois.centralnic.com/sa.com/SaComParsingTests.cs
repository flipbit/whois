using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.SaCom
{
    [TestFixture]
    public class SaComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "sa.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "sa.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("fynbos.sa.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO501005", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Paragon Internet Group", response.Registrar.Name);
            Assert.AreEqual("http://www.paragon.net.uk", response.Registrar.Url);
            Assert.AreEqual("020 3137 7651", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 11, 2, 13, 42, 11, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2007, 9, 27, 18, 14, 53, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 9, 27, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H323273", response.Registrant.RegistryId);
            Assert.AreEqual("Maarten Groos", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("farm 215 fynbos reserve", response.Registrant.Address[0]);
            Assert.AreEqual("PO Box 1314", response.Registrant.Address[1]);
            Assert.AreEqual("Gansbaai", response.Registrant.Address[2]);
            Assert.AreEqual("Western Cape", response.Registrant.Address[3]);
            Assert.AreEqual("7220", response.Registrant.Address[4]);
            Assert.AreEqual("ZA", response.Registrant.Address[5]);

            Assert.AreEqual("+27.283880920", response.Registrant.TelephoneNumber);
            Assert.AreEqual("maarten@farm215.co.za", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("H323273", response.AdminContact.RegistryId);
            Assert.AreEqual("Maarten Groos", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("farm 215 fynbos reserve", response.AdminContact.Address[0]);
            Assert.AreEqual("PO Box 1314", response.AdminContact.Address[1]);
            Assert.AreEqual("Gansbaai", response.AdminContact.Address[2]);
            Assert.AreEqual("Western Cape", response.AdminContact.Address[3]);
            Assert.AreEqual("7220", response.AdminContact.Address[4]);
            Assert.AreEqual("ZA", response.AdminContact.Address[5]);

            Assert.AreEqual("+27.283880920", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("maarten@farm215.co.za", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("C30342", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Seb de Lemos", response.TechnicalContact.Name);
            Assert.AreEqual("Paragon Internet Group", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("St Andrew's House", response.TechnicalContact.Address[0]);
            Assert.AreEqual("St Mary's Walk", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Maidenhead", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Berkshire", response.TechnicalContact.Address[3]);
            Assert.AreEqual("SL6 1QZ", response.TechnicalContact.Address[4]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[5]);

            Assert.AreEqual("+44.2031377651", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domains@paragon.net.uk", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1191.websitewelcome.com", response.NameServers[0]);
            Assert.AreEqual("ns1192.websitewelcome.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(44, response.FieldsParsed);
        }
    }
}
