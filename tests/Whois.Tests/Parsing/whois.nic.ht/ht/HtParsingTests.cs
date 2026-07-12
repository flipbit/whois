using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ht.Ht
{
    public class HtParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public HtParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ht", "ht", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.ht", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/04", response.TemplateName);

            Assert.Equal("u34jedzcq.ht", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ht", "ht", "found", "found.txt");
            var response = parser.Parse("whois.nic.ht", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.ht", response.DomainName.ToString());
            Assert.Equal("112029-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.nic.ht", response.Registrar.WhoisServer.Value);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 05, 16, 09, 18, 24, 192, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 06, 17, 23, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 06, 17, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("88185-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
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
            Assert.Equal("88185-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("Google Inc.", response.AdminContact.Name);
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
            Assert.Equal("182402-CoCCA", response.BillingContact.RegistryId);
            Assert.Equal("eMarkmonitor Inc. dba MarkMonitor", response.BillingContact.Name);
            Assert.Equal("+1.2083895799", response.BillingContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("PMB 155", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("Idaho 83709", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("88185-CoCCA", response.TechnicalContact.RegistryId);
            Assert.Equal("Google Inc.", response.TechnicalContact.Name);
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
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[3]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(62, response.FieldsParsed);
        }
    }
}
