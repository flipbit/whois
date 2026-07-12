using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Vc
{
    public class VcParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public VcParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "vc", "not-found", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(1, response.FieldsParsed);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "vc", "found", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.vc", response.DomainName.ToString());
            Assert.Equal("D133753-LRCC", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

            Assert.Equal(new DateTime(2009, 02, 17, 17, 43, 40, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2005, 06, 29, 00, 58, 18, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2011, 06, 29, 00, 58, 18, 000, DateTimeKind.Utc), response.Expiration);

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
            Assert.Equal("mmr-32102", response.BillingContact.RegistryId);
            Assert.Equal("domain admin", response.BillingContact.Name);
            Assert.Equal("DNStination, Inc.", response.BillingContact.Organization);
            Assert.Equal("+1.4155319335", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895740", response.BillingContact.FaxNumber);
            Assert.Equal("admin@dnstinations.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(6, response.BillingContact.Address.Count);
            Assert.Equal("303 Second Street", response.BillingContact.Address[0]);
            Assert.Equal("Suite 800N", response.BillingContact.Address[1]);
            Assert.Equal("San Francisco", response.BillingContact.Address[2]);
            Assert.Equal("CA", response.BillingContact.Address[3]);
            Assert.Equal("94107", response.BillingContact.Address[4]);
            Assert.Equal("US", response.BillingContact.Address[5]);


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

            Assert.Equal(59, response.FieldsParsed);
        }
    }
}
