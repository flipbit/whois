using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Dm.Dm
{
    public class DmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public DmParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.dm", "dm", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.dm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.dm/dm/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.dm", "dm", "found", "google.dm.txt");
            var response = parser.Parse("whois.nic.dm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.dm/dm/found/01", response.TemplateName);

            Assert.Equal("google.dm", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 07, 23, 17, 50, 34, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 08, 23, 23, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 08, 23, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("P-CQG21", response.Registrant.RegistryId);
            Assert.Equal("Company Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("94043", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("P-DNA22", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("94043", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("P-DXA21", response.BillingContact.RegistryId);
            Assert.Equal("DNS Admin", response.BillingContact.Name);
            Assert.Equal("Google Inc.", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("1600 Amphitheatre", response.BillingContact.Address[0]);
            Assert.Equal("Mountain View", response.BillingContact.Address[1]);
            Assert.Equal("94043", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("P-DXA21", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
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
            Assert.Equal("ACTIVE", response.DomainStatus[0]);

            Assert.Equal(39, response.FieldsParsed);
        }
    }
}
