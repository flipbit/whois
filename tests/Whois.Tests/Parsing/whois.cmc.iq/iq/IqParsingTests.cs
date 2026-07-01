using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cmc.Iq.Iq
{
    [TestFixture]
    public class IqParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.cmc.iq", "iq", "not_found.txt");
            var response = parser.Parse("whois.cmc.iq", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cmc.iq/iq/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.iq", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("No Object Found", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cmc.iq", "iq", "found.txt");
            var response = parser.Parse("whois.cmc.iq", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cmc.iq/iq/Found", response.TemplateName);

            Assert.AreEqual("google.iq", response.DomainName.ToString());
            Assert.AreEqual("895-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("CMC Registrar", response.Registrar.Name);
            Assert.AreEqual("whois.cmc.iq", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2013, 09, 29, 05, 19, 04, 997, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 10, 03, 21, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 02, 21, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("1443-cmc", response.Registrant.RegistryId);
            Assert.AreEqual("Dr.akraym al-hak baker", response.Registrant.Name);
            Assert.AreEqual("+964.7901790160", response.Registrant.TelephoneNumber);
            Assert.AreEqual("bl-yoban@yahoo.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("al-yarmuk", response.Registrant.Address[0]);
            Assert.AreEqual("baghdad", response.Registrant.Address[1]);
            Assert.AreEqual("IQ", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("2640-cmc", response.AdminContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(23, response.FieldsParsed);
        }
    }
}
