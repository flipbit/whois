using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fr.Yt
{
    [TestFixture]
    public class YtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.nic.fr", "yt", "throttled.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Throttled02", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "yt", "not_found.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound06", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fr", "yt", "found.txt");
            var response = parser.Parse("whois.nic.fr", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found05", response.TemplateName);

            Assert.AreEqual("nic.yt", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("AFNIC registry", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2016, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1995, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 12, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("AC3598-FRNIC", response.Registrant.RegistryId);
            Assert.AreEqual("Afnic (Mayotte - CTOM)", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("immeuble international", response.Registrant.Address[0]);
            Assert.AreEqual("2, rue Stephenson", response.Registrant.Address[1]);
            Assert.AreEqual("Montigny-Le-Bretonneux", response.Registrant.Address[2]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.Registrant.Address[3]);
            Assert.AreEqual("FR", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("NFC1-FRNIC", response.AdminContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.AdminContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("AFNIC", response.AdminContact.Address[0]);
            Assert.AreEqual("immeuble international", response.AdminContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.AdminContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.AdminContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.AdminContact.Address[4]);
            Assert.AreEqual("FR", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("NFC1-FRNIC", response.TechnicalContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.TechnicalContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("AFNIC", response.TechnicalContact.Address[0]);
            Assert.AreEqual("immeuble international", response.TechnicalContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.TechnicalContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.TechnicalContact.Address[4]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[5]);


             // ZoneContact Details
            Assert.AreEqual("NFC1-FRNIC", response.ZoneContact.RegistryId);
            Assert.AreEqual("NIC France Contact", response.ZoneContact.Name);
            Assert.AreEqual("+33 1 39 30 83 00", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@nic.fr", response.ZoneContact.Email);

             // ZoneContact Address
            Assert.AreEqual(6, response.ZoneContact.Address.Count);
            Assert.AreEqual("AFNIC", response.ZoneContact.Address[0]);
            Assert.AreEqual("immeuble international", response.ZoneContact.Address[1]);
            Assert.AreEqual("2, rue Stephenson", response.ZoneContact.Address[2]);
            Assert.AreEqual("Montigny le Bretonneux", response.ZoneContact.Address[3]);
            Assert.AreEqual("78181 Saint Quentin en Yvelines Cedex", response.ZoneContact.Address[4]);
            Assert.AreEqual("FR", response.ZoneContact.Address[5]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.nic.fr", response.NameServers[0]);
            Assert.AreEqual("ns2.nic.fr", response.NameServers[1]);
            Assert.AreEqual("ns3.nic.fr", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(32, response.FieldsParsed);
        }
    }
}
