using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gl.Gl
{
    public class GlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public GlParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.gl", "gl", "not-found", "u34jedzcq.gl.txt");
            var response = parser.Parse("whois.nic.gl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/04", response.TemplateName);

            Assert.Equal("u34jedzcq.gl", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.gl", "gl", "found", "google.gl.txt");
            var response = parser.Parse("whois.nic.gl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.gl", response.DomainName.ToString());
            Assert.Equal("Imp669-GL", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);

            Assert.Equal(new DateTime(2013, 12, 02, 19, 11, 52, 734, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2003, 03, 11, 03, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 01, 01, 03, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("4738-GL", response.Registrant.RegistryId);
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("+1.6303300100", response.Registrant.TelephoneNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(5, response.DomainStatus.Count);
            Assert.Equal("clientRenewProhibited", response.DomainStatus[0]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
            Assert.Equal("ok", response.DomainStatus[3]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[4]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(27, response.FieldsParsed);
        }
    }
}
