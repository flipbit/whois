using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Za.Net.ZaNet
{
    [TestFixture]
    public class ZaNetParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.za.net", "za.net", "not_found.txt");
            var response = parser.Parse("whois.za.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.za.net/za.net/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.za.net", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.za.net", "za.net", "found.txt");
            var response = parser.Parse("whois.za.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.za.net/za.net/Found", response.TemplateName);

            Assert.AreEqual("karnaugh.za.net", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2002, 03, 29, 22, 03, 53, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 03, 29, 22, 03, 53, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2009, 11, 22, 16, 01, 16, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Colin Alston", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("11 Swales Crescent", response.Registrant.Address[0]);
            Assert.AreEqual("Pinetown", response.Registrant.Address[1]);
            Assert.AreEqual("3610", response.Registrant.Address[2]);
            Assert.AreEqual("South Africa", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("Colin Alston", response.AdminContact.Name);
            Assert.AreEqual("7037634", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("diskbox@yifan.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("DAC", response.AdminContact.Address[0]);
            Assert.AreEqual("11 Swales Crecent", response.AdminContact.Address[1]);
            Assert.AreEqual("Pinetown", response.AdminContact.Address[2]);
            Assert.AreEqual("KZN", response.AdminContact.Address[3]);
            Assert.AreEqual("3610", response.AdminContact.Address[4]);
            Assert.AreEqual("South Africa", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("Colin Alston", response.TechnicalContact.Name);
            Assert.AreEqual("7037634", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("diskbox@yifan.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("DAC", response.TechnicalContact.Address[0]);
            Assert.AreEqual("11 Swales Crecent", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Pinetown", response.TechnicalContact.Address[2]);
            Assert.AreEqual("KZN", response.TechnicalContact.Address[3]);
            Assert.AreEqual("3610", response.TechnicalContact.Address[4]);
            Assert.AreEqual("South Africa", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns3.zoneedit.com", response.NameServers[0]);
            Assert.AreEqual("ns5.zoneedit.com", response.NameServers[1]);

            Assert.AreEqual(30, response.FieldsParsed);
        }
    }
}
