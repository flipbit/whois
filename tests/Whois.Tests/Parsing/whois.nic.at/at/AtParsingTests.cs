using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.At.At
{
    public class AtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AtParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.at", "at", "not_found.txt");
            var response = parser.Parse("whois.nic.at", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.at/at/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.at", "at", "found.txt");
            var response = parser.Parse("whois.nic.at", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.at/at/Found", response.TemplateName);

            Assert.Equal("google.at", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 04, 26, 17, 57, 27, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.Equal("GI7803022-NICAT", response.Registrant.RegistryId);

             // AdminContact Details
            Assert.Equal("GI7803024-NICAT", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+16502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+16502530001", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("94043", response.AdminContact.Address[1]);
            Assert.Equal("Mountain View", response.AdminContact.Address[2]);
            Assert.Equal("United States", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("GI1919751-NICAT", response.TechnicalContact.RegistryId);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+16506234000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+16506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("USA-94043", response.TechnicalContact.Address[1]);
            Assert.Equal("Mountain View, CA", response.TechnicalContact.Address[2]);
            Assert.Equal("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(49, response.FieldsParsed);
        }
    }
}
