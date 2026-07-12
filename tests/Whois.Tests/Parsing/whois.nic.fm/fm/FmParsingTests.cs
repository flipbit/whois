using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fm.Fm
{
    public class FmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public FmParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fm", "fm", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.fm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fm", "fm", "found", "google.fm.txt");
            var response = parser.Parse("whois.nic.fm", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.fm", response.DomainName.ToString());
            Assert.Equal("D34865469-CNIC", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor, Inc.", response.Registrar.Name);
            Assert.Equal("292", response.Registrar.IanaId);
            Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2017, 10, 20, 17, 48, 39, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2000, 09, 05, 23, 59, 59, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 09, 04, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("C78398194-CNIC", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google, Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6506181499", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@GOOGLE.COM", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("C78398194-CNIC", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google, Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6503300100", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506181499", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@GOOGLE.COM", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("C78382669-CNIC", response.BillingContact.RegistryId);
            Assert.Equal("Domain Billing", response.BillingContact.Name);
            Assert.Equal("MarkMonitor, Inc", response.BillingContact.Organization);
            Assert.Equal("+1..208389574", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1..20838958", response.BillingContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("10400 Overland Rd, PMB 155", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("ID", response.BillingContact.Address[2]);
            Assert.Equal("83709", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("C78398194-CNIC", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google, Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6506181499", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@GOOGLE.COM", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("CA", response.TechnicalContact.Address[2]);
            Assert.Equal("94043", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns3.google.com", response.NameServers[1]);
            Assert.Equal("ns2.google.com", response.NameServers[2]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(61, response.FieldsParsed);
        }
    }
}
