using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fo.Fo
{
    [TestFixture]
    public class FoParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.fo", "fo", "not_found.txt");
            var response = parser.Parse("whois.nic.fo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.fo/fo/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fo", "fo", "found.txt");
            var response = parser.Parse("whois.nic.fo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.fo/fo/Found", response.TemplateName);

            Assert.AreEqual("nic.fo", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 07, 12, 12, 52, 57, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 06, 03, 03, 34, 05, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("ID005359", response.Registrant.RegistryId);
            Assert.AreEqual("FO-umsitingin", response.Registrant.Name);
            Assert.AreEqual(new DateTime(2010, 07, 21, 19, 11, 55, 000, DateTimeKind.Utc), response.Registrant.Created);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Hoydalsvegur 19, Postboks 1255", response.Registrant.Address[0]);
            Assert.AreEqual("Torshavn", response.Registrant.Address[1]);
            Assert.AreEqual("110", response.Registrant.Address[2]);
            Assert.AreEqual("FO", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("ID005359", response.TechnicalContact.RegistryId);
            Assert.AreEqual("FO-umsitingin", response.TechnicalContact.Name);
            Assert.AreEqual(new DateTime(2010, 07, 21, 19, 11, 55, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Hoydalsvegur 19, Postboks 1255", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Torshavn", response.TechnicalContact.Address[1]);
            Assert.AreEqual("110", response.TechnicalContact.Address[2]);
            Assert.AreEqual("FO", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("ns1.gratisdns.dk", response.NameServers[0]);
            Assert.AreEqual("ns2.gratisdns.dk", response.NameServers[1]);
            Assert.AreEqual("ns3.gratisdns.dk", response.NameServers[2]);
            Assert.AreEqual("ns4.gratisdns.dk", response.NameServers[3]);
            Assert.AreEqual("ns5.gratisdns.dk", response.NameServers[4]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("paid and in zone", response.DomainStatus[0]);

            Assert.AreEqual(21, response.FieldsParsed);
        }
    }
}
