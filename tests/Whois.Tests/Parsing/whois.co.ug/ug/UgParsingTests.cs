using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Ug.Ug
{
    [TestFixture]
    public class UgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "found.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ug/ug/Found", response.TemplateName);

            Assert.AreEqual("whois.co.ug", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 11, 10, 14, 06, 58, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 04, 02, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 04, 07, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("CM260", response.AdminContact.RegistryId);
            Assert.AreEqual("Charles Musisi", response.AdminContact.Name);
            Assert.AreEqual("+256 31 230 1800", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Computer Frontiers International, Plot 6B Windsor Loop, P.O. Box 12", response.AdminContact.Address[0]);
            Assert.AreEqual("Kampala", response.AdminContact.Address[1]);
            Assert.AreEqual("Uganda", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("MJ5-UG", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Mpeirwe Johnson", response.TechnicalContact.Name);
            Assert.AreEqual("+256782694615", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Plot 6B, Windor Loop Kitante", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Kampala", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Uganda", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.cfi.co.ug", response.NameServers[0]);
            Assert.AreEqual("ns2.cfi.co.ug", response.NameServers[1]);
            Assert.AreEqual("ns3.cfi.co.ug", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(23, response.FieldsParsed);
            AssertWriter.Write(response);
        }

        [Test]
        public void Test_unconfirmed()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "unconfirmed.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Unconfirmed, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ug/ug/Found", response.TemplateName);

            Assert.AreEqual("youtube.ug", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 11, 01, 23, 27, 38, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2011, 11, 01, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 11, 01, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("UNCONFIRMED", response.DomainStatus[0]);

            Assert.AreEqual(18, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "not_found.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ug/ug/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.co.ug", "ug", "found_status_registered.txt");
            var response = parser.Parse("whois.co.ug", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.ug/ug/Found", response.TemplateName);

            Assert.AreEqual("whois.co.ug", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 11, 10, 14, 06, 58, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 04, 02, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 04, 07, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("CM260", response.AdminContact.RegistryId);
            Assert.AreEqual("Charles Musisi", response.AdminContact.Name);
            Assert.AreEqual("+256 31 230 1800", response.AdminContact.TelephoneNumber);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Computer Frontiers International, Plot 6B Windsor Loop, P.O. Box 12", response.AdminContact.Address[0]);
            Assert.AreEqual("Kampala", response.AdminContact.Address[1]);
            Assert.AreEqual("Uganda", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("MJ5-UG", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Mpeirwe Johnson", response.TechnicalContact.Name);
            Assert.AreEqual("+256782694615", response.TechnicalContact.TelephoneNumber);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Plot 6B, Windor Loop Kitante", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Kampala", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Uganda", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.cfi.co.ug", response.NameServers[0]);
            Assert.AreEqual("ns2.cfi.co.ug", response.NameServers[1]);
            Assert.AreEqual("ns3.cfi.co.ug", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(23, response.FieldsParsed);
        }
    }
}
