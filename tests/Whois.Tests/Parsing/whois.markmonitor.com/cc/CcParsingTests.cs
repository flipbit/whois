using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Markmonitor.Com.Cc
{
    public class CcParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CcParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.markmonitor.com", "cc", "found", "found.txt");
            var response = parser.Parse("whois.markmonitor.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.cc", response.DomainName.ToString());
            Assert.Equal("86420657_DOMAIN_CC-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor, Inc.", response.Registrar.Name);
            Assert.Equal("292", response.Registrar.IanaId);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);


             // Registrant Details
            Assert.Equal("DNS Admin", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("+1.6506234000", response.Registrant.TelephoneNumber);
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
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6506234000", response.AdminContact.TelephoneNumber);
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
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.6506234000", response.TechnicalContact.TelephoneNumber);
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
            Assert.Equal("ns3.google.com", response.NameServers[0]);
            Assert.Equal("ns4.google.com", response.NameServers[1]);
            Assert.Equal("ns2.google.com", response.NameServers[2]);
            Assert.Equal("ns1.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(6, response.DomainStatus.Count);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[2]);
            Assert.Equal("serverUpdateProhibited", response.DomainStatus[3]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[4]);
            Assert.Equal("serverDeleteProhibited", response.DomainStatus[5]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(56, response.FieldsParsed);
        }
    }
}
