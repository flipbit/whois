using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ms.Ms
{
    public class MsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public MsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ms", "ms", "not_found.txt");
            var response = parser.Parse("whois.nic.ms", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound004", response.TemplateName);

            Assert.Equal("u34jedzcq.ms", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ms", "ms", "found.txt");
            var response = parser.Parse("whois.nic.ms", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.ms", response.DomainName.ToString());
            Assert.Equal("23725-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 12, 06, 08, 14, 24, 368, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 06, 04, 12, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 06, 04, 12, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("313268-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("Google, Inc.", response.Registrant.Name);
            Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("313268-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("Google, Inc.", response.AdminContact.Name);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("94043", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("313269-CoCCA", response.BillingContact.RegistryId);
            Assert.Equal("MarkMonitor", response.BillingContact.Name);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("10400 Overland Rd.", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("ID 83709-1433", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(5, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
            Assert.Equal("clientRenewProhibited", response.DomainStatus[3]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[4]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(46, response.FieldsParsed);
        }
    }
}
