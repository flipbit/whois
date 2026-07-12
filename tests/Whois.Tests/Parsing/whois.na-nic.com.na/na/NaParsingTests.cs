using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Na.Nic.Com.Na.Na
{
    public class NaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public NaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.na-nic.com.na", "na", "not-found", "u34jedzcq.na.txt");
            var response = parser.Parse("whois.na-nic.com.na", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/04", response.TemplateName);

            Assert.Equal("u34jedzcq.na", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.na-nic.com.na", "na", "found", "google.na.txt");
            var response = parser.Parse("whois.na-nic.com.na", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.na", response.DomainName.ToString());
            Assert.Equal("4100-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 07, 22, 17, 07, 58, 776, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2007, 03, 27, 22, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 08, 19, 23, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("11969-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("Google Inc", response.Registrant.Name);
            Assert.Equal("info@google.na", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("11898-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("Christina Chiou", response.AdminContact.Name);
            Assert.Equal("Google Inc", response.AdminContact.Organization);
            Assert.Equal("+1.6503300100", response.AdminContact.TelephoneNumber);
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
            Assert.Equal("11871-CoCCA", response.TechnicalContact.RegistryId);
            Assert.Equal("CCOPS Provisioning", response.TechnicalContact.Name);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("10400 Overland Road, PMB 155", response.TechnicalContact.Address[0]);
            Assert.Equal("Boise, ID 83709", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.google.com", response.NameServers[0]);
            Assert.Equal("ns1.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(5, response.DomainStatus.Count);
            Assert.Equal("clientRenewProhibited", response.DomainStatus[0]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.Equal("ok", response.DomainStatus[2]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[3]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[4]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(43, response.FieldsParsed);
        }
    }
}
