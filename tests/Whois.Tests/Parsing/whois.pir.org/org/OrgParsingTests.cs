using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Pir.Org.Org
{
    public class OrgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public OrgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.pir.org", "org", "throttled", "throttled.txt");
            var response = parser.Parse("whois.pir.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Throttled, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/throttled/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.pir.org", "org", "not-found", "not_found.txt");
            var response = parser.Parse("whois.pir.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.pir.org", "org", "found", "found.txt");
            var response = parser.Parse("whois.pir.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.org", response.DomainName.ToString());
            Assert.Equal("D2244233-LROR", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor Inc. (R37-LROR)", response.Registrar.Name);
            Assert.Equal("292", response.Registrar.IanaId);

            Assert.Equal(new DateTime(2013, 09, 18, 09, 17, 35, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1998, 10, 21, 04, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 10, 20, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("mmr-32097", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6506234000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("mmr-32097", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6506234000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("mmr-32097", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6506234000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
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
            Assert.Equal("ns2.google.com", response.NameServers[0]);
            Assert.Equal("ns1.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(49, response.FieldsParsed);
        }
    }
}
