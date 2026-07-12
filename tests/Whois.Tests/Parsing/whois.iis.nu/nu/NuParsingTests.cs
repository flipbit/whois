using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iis.Nu.Nu
{
    public class NuParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public NuParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.iis.nu", "nu", "not-found", "u34jedzcq.nu.txt");
            var response = parser.Parse("whois.iis.nu", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.iis.nu/nu/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.nu", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.iis.nu", "nu", "found", "google.nu.txt");
            var response = parser.Parse("whois.iis.nu", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.iis.nu/nu/found/01", response.TemplateName);

            Assert.Equal("google.nu", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 05, 06, 00, 00, 00, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1999, 06, 07, 00, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 06, 07, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("mmr-142621", response.Registrant.RegistryId);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned delegation", response.DnsSecStatus);
            Assert.Equal(13, response.FieldsParsed);
        }
    }
}
