using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois1.Nic.Bi.Bi
{
    public class BiParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BiParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois1.nic.bi", "bi", "not-found", "u34jedzcq.bi.txt");
            var response = parser.Parse("whois1.nic.bi", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/04", response.TemplateName);

            Assert.Equal("u34jedzcq.bi", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois1.nic.bi", "bi", "found", "google.bi.txt");
            var response = parser.Parse("whois1.nic.bi", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.bi", response.DomainName.ToString());
            Assert.Equal("2633NIC-BI", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonito", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 12, 05, 07, 16, 04, 538, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2002, 09, 29, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 09, 29, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("85593NIC-BI", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6506234000", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("85593NIC-BI", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6506234000", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("85594NIC-BI", response.BillingContact.RegistryId);
            Assert.Equal("MM Domain Administrator", response.BillingContact.Name);
            Assert.Equal("MarkMonitor Inc", response.BillingContact.Organization);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("391 N Ancestor Place", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("Idaho", response.BillingContact.Address[2]);
            Assert.Equal("83704", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("85593NIC-BI", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6506234000", response.TechnicalContact.TelephoneNumber);
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
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(53, response.FieldsParsed);
        }
    }
}
