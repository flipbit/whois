using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Inregistry.Net.In
{
    [TestFixture]
    public class InParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.inregistry.net", "in", "not_found.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "found.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("videogratis.in", response.DomainName.ToString());
            Assert.AreEqual("D3271170-AFIN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("GoDaddy.com Inc. (R101-AFIN)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 07, 01, 12, 55, 17, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 01, 27, 05, 01, 05, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 01, 27, 05, 01, 05, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("CR51214064", response.Registrant.RegistryId);
            Assert.AreEqual("claudio spada", response.Registrant.Name);
            Assert.AreEqual("sirismedia", response.Registrant.Organization);
            Assert.AreEqual("+91.03902861317", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domini@siris.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("foro buonaparte 69", response.Registrant.Address[0]);
            Assert.AreEqual("milano", response.Registrant.Address[1]);
            Assert.AreEqual("italy", response.Registrant.Address[2]);
            Assert.AreEqual("20121", response.Registrant.Address[3]);
            Assert.AreEqual("AX", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("CR51214074", response.AdminContact.RegistryId);
            Assert.AreEqual("claudio spada", response.AdminContact.Name);
            Assert.AreEqual("sirismedia", response.AdminContact.Organization);
            Assert.AreEqual("+91.03902861317", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domini@siris.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("foro buonaparte 69", response.AdminContact.Address[0]);
            Assert.AreEqual("milano", response.AdminContact.Address[1]);
            Assert.AreEqual("italy", response.AdminContact.Address[2]);
            Assert.AreEqual("20121", response.AdminContact.Address[3]);
            Assert.AreEqual("AX", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("CR51214069", response.TechnicalContact.RegistryId);
            Assert.AreEqual("claudio spada", response.TechnicalContact.Name);
            Assert.AreEqual("sirismedia", response.TechnicalContact.Organization);
            Assert.AreEqual("+91.03902861317", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domini@siris.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("foro buonaparte 69", response.TechnicalContact.Address[0]);
            Assert.AreEqual("milano", response.TechnicalContact.Address[1]);
            Assert.AreEqual("italy", response.TechnicalContact.Address[2]);
            Assert.AreEqual("20121", response.TechnicalContact.Address[3]);
            Assert.AreEqual("AX", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.slicehost.net", response.NameServers[0]);
            Assert.AreEqual("ns2.slicehost.net", response.NameServers[1]);
            Assert.AreEqual("ns3.slicehost.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT RENEW PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[3]);

            Assert.AreEqual(44, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "found_status_ok.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.in", response.DomainName.ToString());
            Assert.AreEqual("D21089-AFIN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Mark Monitor (R84-AFIN)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2009, 04, 06, 18, 20, 09, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("EPPIPM-143349", response.Registrant.RegistryId);
            Assert.AreEqual("Admin DNS", response.Registrant.Name);
            Assert.AreEqual("GOOGLE INC.", response.Registrant.Organization);
            Assert.AreEqual("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA", response.Registrant.Address[1]);
            Assert.AreEqual("94043", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("EPPIPM-143349", response.AdminContact.RegistryId);
            Assert.AreEqual("Admin DNS", response.AdminContact.Name);
            Assert.AreEqual("GOOGLE INC.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View, CA", response.AdminContact.Address[1]);
            Assert.AreEqual("94043", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("EPPIPM-143349", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Admin DNS", response.TechnicalContact.Name);
            Assert.AreEqual("GOOGLE INC.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View, CA", response.TechnicalContact.Address[1]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual(39, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "not_found_status_available.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "found_status_registered.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.in", response.DomainName.ToString());
            Assert.AreEqual("D21089-AFIN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Mark Monitor (R84-AFIN)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2015, 01, 13, 10, 22, 36, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("mmr-108695", response.Registrant.RegistryId);
            Assert.AreEqual("Christina Chiou", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("mmr-108695", response.AdminContact.RegistryId);
            Assert.AreEqual("Christina Chiou", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("mmr-108695", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Christina Chiou", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6502530001", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.AreEqual("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(48, response.FieldsParsed);
        }
    }
}
