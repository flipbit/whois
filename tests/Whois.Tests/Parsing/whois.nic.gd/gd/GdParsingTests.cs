using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gd.Gd
{
    public class GdParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public GdParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.gd", "gd", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.gd", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.gd/gd/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.gd", "gd", "found", "google.gd.txt");
            var response = parser.Parse("whois.nic.gd", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.gd/gd/found/01", response.TemplateName);

            Assert.Equal("google.gd", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2013, 11, 12, 16, 07, 05, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 12, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 12, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("P-GXI35", response.Registrant.RegistryId);
            Assert.Equal("Google, Inc.", response.Registrant.Name);
            Assert.Equal("Google, Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6503300100", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6506181499", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("94043", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("P-GXI35", response.AdminContact.RegistryId);
            Assert.Equal("Google, Inc.", response.AdminContact.Name);
            Assert.Equal("Google, Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6506181499", response.AdminContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("94043", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("UNKNOWN MarkMonitor", response.BillingContact.Name);
            Assert.Equal("MarkMonitor", response.BillingContact.Organization);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("10400 Overland Road", response.BillingContact.Address[0]);
            Assert.Equal("Idaho", response.BillingContact.Address[1]);
            Assert.Equal("83709", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("P-GXI35", response.TechnicalContact.RegistryId);
            Assert.Equal("Google, Inc.", response.TechnicalContact.Name);
            Assert.Equal("Google, Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6506181499", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("94043", response.TechnicalContact.Address[2]);
            Assert.Equal("US", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientupdateprohibited", response.DomainStatus[0]);
            Assert.Equal("clienttransferprohibited", response.DomainStatus[1]);

            Assert.Equal(50, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.gd", "gd", "reserved", "reserved.txt");
            var response = parser.Parse("whois.nic.gd", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.gd/gd/reserved/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }
    }
}
