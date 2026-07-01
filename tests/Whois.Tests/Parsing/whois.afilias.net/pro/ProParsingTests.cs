using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Net.Pro
{
    public class ProParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ProParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.afilias.net", "pro", "not_found.txt");
            var response = parser.Parse("whois.afilias.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias.net", "pro", "found.txt");
            var response = parser.Parse("whois.afilias.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.pro", response.DomainName.ToString());
            Assert.Equal("D107300000000011545-LRMS", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("292", response.Registrar.IanaId);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2016, 02, 01, 15, 44, 03, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2016, 09, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("mmr-2383", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
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
            Assert.Equal("mmr-2383", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("mmr-132627", response.BillingContact.RegistryId);
            Assert.Equal("CCOPS Billing", response.BillingContact.Name);
            Assert.Equal("MarkMonitor, Inc.", response.BillingContact.Organization);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("391 N. Ancestor Place", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("ID", response.BillingContact.Address[2]);
            Assert.Equal("83704", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("mmr-2383", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
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
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(59, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.afilias.net", "pro", "reserved.txt");
            var response = parser.Parse("whois.afilias.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);
        }
    }
}
