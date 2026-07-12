using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.St.St
{
    public class StParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public StParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.st", "st", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.st", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.st/st/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.st", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.st", "st", "found", "found.txt");
            var response = parser.Parse("whois.nic.st", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.st/st/found/01", response.TemplateName);

            Assert.Equal("google.st", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2017, 05, 14, 09, 28, 07, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 06, 15, 18, 24, 45, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 06, 15, 18, 24, 45, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("DNS Admin (mm-87489)", response.Registrant.Name);
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
            Assert.Equal("DNS Admin (mm-87489)", response.AdminContact.Name);
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
            Assert.Equal("Domain Provisioning (MAR52541B369EEFE)", response.BillingContact.Name);
            Assert.Equal("Mark Monitor", response.BillingContact.Organization);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("10400 Overland Road", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("83709", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("DNS Admin (mm-87489)", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.6502530001", response.TechnicalContact.FaxNumber);
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
            Assert.Equal("ns3.google.com", response.NameServers[0]);
            Assert.Equal("ns1.google.com", response.NameServers[1]);
            Assert.Equal("ns4.google.com", response.NameServers[2]);
            Assert.Equal("ns2.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);

            Assert.Equal(54, response.FieldsParsed);
        }
    }
}
