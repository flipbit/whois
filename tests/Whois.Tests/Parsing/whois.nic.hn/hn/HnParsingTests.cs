using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Hn.Hn
{
    public class HnParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public HnParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.hn", "hn", "not_found.txt");
            var response = parser.Parse("whois.nic.hn", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound004", response.TemplateName);

            Assert.Equal("u34jedzcq.hn", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.hn", "hn", "found.txt");
            var response = parser.Parse("whois.nic.hn", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.hn", response.DomainName.ToString());
            Assert.Equal("801220-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.nic.hn", response.Registrar.WhoisServer.Value);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2014, 02, 03, 10, 22, 23, 197, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2003, 03, 07, 05, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 03, 07, 05, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("490793-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("DNS Admin", response.Registrant.Name);
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
            Assert.Equal("490793-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("DNS Admin", response.AdminContact.Name);
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


             // BillingContact Details
            Assert.Equal("857074-CoCCA", response.BillingContact.RegistryId);
            Assert.Equal("CCOPs Provisioning", response.BillingContact.Name);
            Assert.Equal("MarkMonitor", response.BillingContact.Organization);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("10400 Overland Rd PMB 155", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("ID", response.BillingContact.Address[2]);
            Assert.Equal("83709", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("857074-CoCCA", response.TechnicalContact.RegistryId);
            Assert.Equal("CCOPs Provisioning", response.TechnicalContact.Name);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
            Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("10400 Overland Rd PMB 155", response.TechnicalContact.Address[0]);
            Assert.Equal("Boise", response.TechnicalContact.Address[1]);
            Assert.Equal("ID", response.TechnicalContact.Address[2]);
            Assert.Equal("83709", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

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
