using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Amnic.Net.Am
{
    public class AmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AmParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.amnic.net", "am", "not-found", "not_found.txt");
            var response = parser.Parse("whois.amnic.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.amnic.net", "am", "found", "google.am.txt");
            var response = parser.Parse("whois.amnic.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(31, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.amnic.net/am/found/01", response.TemplateName);

            Assert.Equal("google.am", response.DomainName.ToString());
            Assert.Equal("abcdomain", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 2, 13, 0, 0, 0), response.Updated);
            Assert.Equal(new DateTime(1999, 6, 5, 0, 0, 0), response.Registered);
            Assert.Equal(new DateTime(2014, 4, 15, 0, 0, 0), response.Expiration);
            Assert.Equal("Google, Inc.", response.Registrant.Name);

            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, CA,  94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


            Assert.Equal("Google, Inc.", response.AdminContact.Name);
            Assert.Equal("Google, Inc.", response.AdminContact.Organization);

            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View, CA, 94043", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);

            Assert.Equal("1 6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("1 6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google, Inc.", response.TechnicalContact.Organization);

            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View, CA, 94043", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);

            Assert.Equal("1 6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("1 6506188571", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);


            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("active", response.DomainStatus[0]);
        }
    }
}
