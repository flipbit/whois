using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Donuts.Co.Bike
{
    [TestFixture]
    public class BikeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.donuts.co", "bike", "not_found.txt");
            var response = parser.Parse("whois.donuts.co", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound003", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.donuts.co", "bike", "found.txt");
            var response = parser.Parse("whois.donuts.co", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("whereismy.bike", response.DomainName.ToString());
            Assert.AreEqual("e25432d5c94440c4a8ca0e5ecbc13904-DONUTS", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("GoDaddy.com, LLC", response.Registrar.Name);
            Assert.AreEqual("146", response.Registrar.IanaId);
            Assert.AreEqual("http://www.godaddy.com/domains/search.aspx?ci=8990", response.Registrar.Url);
            Assert.AreEqual("who.godaddy.com", response.Registrar.WhoisServer.Value);
            Assert.AreEqual("abuse@godaddy.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.4806242505", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2017, 04, 12, 16, 49, 41, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2016, 02, 26, 16, 49, 10, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 02, 26, 16, 49, 10, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("2a94fd50b2ca42c685828dfa8c07e23d-DONUTS", response.Registrant.RegistryId);
            Assert.AreEqual("Marko Matenda", response.Registrant.Name);
            Assert.AreEqual("+385.916283632", response.Registrant.TelephoneNumber);
            Assert.AreEqual("marko.matenda@gmail.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("Ante Starcevica 9.", response.Registrant.Address[0]);
            Assert.AreEqual("Bjelovar", response.Registrant.Address[1]);
            Assert.AreEqual("Croatia", response.Registrant.Address[2]);
            Assert.AreEqual("43000", response.Registrant.Address[3]);
            Assert.AreEqual("HR", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("a627ad7dc57343858c4397b9e3f9a530-DONUTS", response.AdminContact.RegistryId);
            Assert.AreEqual("Marko Matenda", response.AdminContact.Name);
            Assert.AreEqual("+385.916283632", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("marko.matenda@gmail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Ante Starcevica 9.", response.AdminContact.Address[0]);
            Assert.AreEqual("Bjelovar", response.AdminContact.Address[1]);
            Assert.AreEqual("Croatia", response.AdminContact.Address[2]);
            Assert.AreEqual("43000", response.AdminContact.Address[3]);
            Assert.AreEqual("HR", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("08094e7dd78143d6b83338c5c59a8160-DONUTS", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Marko Matenda", response.TechnicalContact.Name);
            Assert.AreEqual("+385.916283632", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("marko.matenda@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ante Starcevica 9.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Bjelovar", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Croatia", response.TechnicalContact.Address[2]);
            Assert.AreEqual("43000", response.TechnicalContact.Address[3]);
            Assert.AreEqual("HR", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns68.domaincontrol.com", response.NameServers[0]);
            Assert.AreEqual("ns67.domaincontrol.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[3]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(49, response.FieldsParsed);
        }
    }
}
