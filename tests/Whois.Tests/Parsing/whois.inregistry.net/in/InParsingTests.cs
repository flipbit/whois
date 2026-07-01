using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Inregistry.Net.In
{
    public class InParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public InParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "not_found.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound001", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "found.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("videogratis.in", response.DomainName.ToString());
            Assert.Equal("D3271170-AFIN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("GoDaddy.com Inc. (R101-AFIN)", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 07, 01, 12, 55, 17, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2009, 01, 27, 05, 01, 05, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 01, 27, 05, 01, 05, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("CR51214064", response.Registrant.RegistryId);
            Assert.Equal("claudio spada", response.Registrant.Name);
            Assert.Equal("sirismedia", response.Registrant.Organization);
            Assert.Equal("+91.03902861317", response.Registrant.TelephoneNumber);
            Assert.Equal("domini@siris.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("foro buonaparte 69", response.Registrant.Address[0]);
            Assert.Equal("milano", response.Registrant.Address[1]);
            Assert.Equal("italy", response.Registrant.Address[2]);
            Assert.Equal("20121", response.Registrant.Address[3]);
            Assert.Equal("AX", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("CR51214074", response.AdminContact.RegistryId);
            Assert.Equal("claudio spada", response.AdminContact.Name);
            Assert.Equal("sirismedia", response.AdminContact.Organization);
            Assert.Equal("+91.03902861317", response.AdminContact.TelephoneNumber);
            Assert.Equal("domini@siris.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("foro buonaparte 69", response.AdminContact.Address[0]);
            Assert.Equal("milano", response.AdminContact.Address[1]);
            Assert.Equal("italy", response.AdminContact.Address[2]);
            Assert.Equal("20121", response.AdminContact.Address[3]);
            Assert.Equal("AX", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("CR51214069", response.TechnicalContact.RegistryId);
            Assert.Equal("claudio spada", response.TechnicalContact.Name);
            Assert.Equal("sirismedia", response.TechnicalContact.Organization);
            Assert.Equal("+91.03902861317", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("domini@siris.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("foro buonaparte 69", response.TechnicalContact.Address[0]);
            Assert.Equal("milano", response.TechnicalContact.Address[1]);
            Assert.Equal("italy", response.TechnicalContact.Address[2]);
            Assert.Equal("20121", response.TechnicalContact.Address[3]);
            Assert.Equal("AX", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.slicehost.net", response.NameServers[0]);
            Assert.Equal("ns2.slicehost.net", response.NameServers[1]);
            Assert.Equal("ns3.slicehost.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.Equal("CLIENT RENEW PROHIBITED", response.DomainStatus[1]);
            Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[2]);
            Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[3]);

            Assert.Equal(44, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_ok()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "found_status_ok.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.in", response.DomainName.ToString());
            Assert.Equal("D21089-AFIN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Mark Monitor (R84-AFIN)", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 04, 06, 18, 20, 09, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2005, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("EPPIPM-143349", response.Registrant.RegistryId);
            Assert.Equal("Admin DNS", response.Registrant.Name);
            Assert.Equal("GOOGLE INC.", response.Registrant.Organization);
            Assert.Equal("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA", response.Registrant.Address[1]);
            Assert.Equal("94043", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("EPPIPM-143349", response.AdminContact.RegistryId);
            Assert.Equal("Admin DNS", response.AdminContact.Name);
            Assert.Equal("GOOGLE INC.", response.AdminContact.Organization);
            Assert.Equal("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View, CA", response.AdminContact.Address[1]);
            Assert.Equal("94043", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("EPPIPM-143349", response.TechnicalContact.RegistryId);
            Assert.Equal("Admin DNS", response.TechnicalContact.Name);
            Assert.Equal("GOOGLE INC.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View, CA", response.TechnicalContact.Address[1]);
            Assert.Equal("94043", response.TechnicalContact.Address[2]);
            Assert.Equal("US", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("OK", response.DomainStatus[0]);

            Assert.Equal(39, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "not_found_status_available.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound001", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.inregistry.net", "in", "found_status_registered.txt");
            var response = parser.Parse("whois.inregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.in", response.DomainName.ToString());
            Assert.Equal("D21089-AFIN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Mark Monitor (R84-AFIN)", response.Registrar.Name);

            Assert.Equal(new DateTime(2015, 01, 13, 10, 22, 36, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2005, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2016, 02, 14, 20, 35, 14, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("mmr-108695", response.Registrant.RegistryId);
            Assert.Equal("Christina Chiou", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("mmr-108695", response.AdminContact.RegistryId);
            Assert.Equal("Christina Chiou", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6502530001", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("mmr-108695", response.TechnicalContact.RegistryId);
            Assert.Equal("Christina Chiou", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6502530001", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("CA", response.TechnicalContact.Address[2]);
            Assert.Equal("94043", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(48, response.FieldsParsed);
        }
    }
}
