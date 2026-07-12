using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Verisign.Grs.Com.Net
{
    public class NetParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public NetParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "net", "not-found", "u34jedzcq.net.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/07", response.TemplateName);

            Assert.Equal("u34jedzcq.net", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.verisign-grs.com", "net", "found", "google.net.txt");
            var response = parser.Parse("whois.verisign-grs.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/02", response.TemplateName);

            Assert.Equal("google.net", response.DomainName.ToString());
            Assert.Equal("4802712_DOMAIN_NET-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("292", response.Registrar.IanaId);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
            Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
            Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2017, 02, 11, 10, 56, 37, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 03, 15, 05, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2018, 03, 15, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(6, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
            Assert.Equal("serverDeleteProhibited", response.DomainStatus[3]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[4]);
            Assert.Equal("serverUpdateProhibited", response.DomainStatus[5]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(23, response.FieldsParsed);
        }
    }
}
