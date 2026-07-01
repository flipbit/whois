using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cx.Cx
{
    public class CxParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CxParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.cx", "cx", "found.txt");
            var response = parser.Parse("whois.nic.cx", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("communication.cx", response.DomainName.ToString());
            Assert.Equal("919354-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Marcaria.com", response.Registrar.Name);
            Assert.Equal("whois.nic.cx", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2013, 07, 17, 10, 26, 59, 132, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 07, 17, 10, 26, 59, 365, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("919353-CoCCA", response.Registrant.RegistryId);
            Assert.Equal("Matthew Marks", response.Registrant.Name);
            Assert.Equal("+1.3054348621", response.Registrant.TelephoneNumber);
            Assert.Equal("domains@marcaria.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("162 Locarna Way", response.Registrant.Address[0]);
            Assert.Equal("Pittsburgh", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("99834-CoCCA", response.AdminContact.RegistryId);
            Assert.Equal("Francisco Fuentealba", response.AdminContact.Name);
            Assert.Equal("domains@marcaria.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("UNKNOWN", response.AdminContact.Address[0]);
            Assert.Equal("Miami", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("99834-CoCCA", response.BillingContact.RegistryId);
            Assert.Equal("Francisco Fuentealba", response.BillingContact.Name);
            Assert.Equal("domains@marcaria.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("UNKNOWN", response.BillingContact.Address[0]);
            Assert.Equal("Miami", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("99834-CoCCA", response.TechnicalContact.RegistryId);
            Assert.Equal("Francisco Fuentealba", response.TechnicalContact.Name);
            Assert.Equal("domains@marcaria.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("UNKNOWN", response.TechnicalContact.Address[0]);
            Assert.Equal("Miami", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns01.trademarkarea.com", response.NameServers[0]);
            Assert.Equal("ns02.trademarkarea.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(36, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.cx", "cx", "not_found.txt");
            var response = parser.Parse("whois.nic.cx", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound004", response.TemplateName);

            Assert.Equal("u34jedzcq.cx", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.cx", "cx", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.cx", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.cx", response.DomainName.ToString());
            Assert.Equal("447518-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("whois.nic.cx", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2014, 06, 28, 09, 18, 02, 516, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 07, 29, 18, 15, 42, 056, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 07, 29, 18, 15, 42, 158, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("969680-CoCCA", response.Registrant.RegistryId);
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
            Assert.Equal("969680-CoCCA", response.AdminContact.RegistryId);
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


             // TechnicalContact Details
            Assert.Equal("969680-CoCCA", response.TechnicalContact.RegistryId);
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
            Assert.Equal("ns3.google.com", response.NameServers[1]);
            Assert.Equal("ns4.google.com", response.NameServers[2]);
            Assert.Equal("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("ok", response.DomainStatus[2]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[3]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(50, response.FieldsParsed);
        }
    }
}
