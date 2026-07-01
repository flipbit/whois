using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Sc
{
    public class ScParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ScParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "sc", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(1, response.FieldsParsed);
            Assert.Equal("generic/tld/NotFound001", response.TemplateName);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "sc", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("google.sc", response.DomainName.ToString());
            Assert.Equal("D47234-LRCC", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor, Inc. (R22-LRCC)", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 01, 02, 10, 20, 29, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 02, 03, 19, 19, 12, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 02, 03, 19, 19, 12, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("AGRS-129819", response.Registrant.RegistryId);
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
            Assert.Equal("AGRS-129293", response.AdminContact.RegistryId);
            Assert.Equal("CCOPS", response.AdminContact.Name);
            Assert.Equal("MarkMonitor", response.AdminContact.Organization);
            Assert.Equal("+1.20838957", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.20838957", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("PMB 155", response.AdminContact.Address[0]);
            Assert.Equal("10400 Overland Rd.", response.AdminContact.Address[1]);
            Assert.Equal("Boise", response.AdminContact.Address[2]);
            Assert.Equal("ID", response.AdminContact.Address[3]);
            Assert.Equal("83709-1433", response.AdminContact.Address[4]);
            Assert.Equal("US", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("mmr-33293", response.TechnicalContact.RegistryId);
            Assert.Equal("Domain Admin", response.TechnicalContact.Name);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
            Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("391 N. Ancestor Place", response.TechnicalContact.Address[0]);
            Assert.Equal("Suite 150", response.TechnicalContact.Address[1]);
            Assert.Equal("Boise", response.TechnicalContact.Address[2]);
            Assert.Equal("CA", response.TechnicalContact.Address[3]);
            Assert.Equal("83704", response.TechnicalContact.Address[4]);
            Assert.Equal("US", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);
            Assert.Equal("CLIENT UPDATE PROHIBITED", response.DomainStatus[2]);
            Assert.Equal("RENEWPERIOD", response.DomainStatus[3]);

            Assert.Equal(48, response.FieldsParsed);
        }
    }
}
