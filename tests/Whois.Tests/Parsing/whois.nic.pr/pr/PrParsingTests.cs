using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Pr.Pr
{
    public class PrParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public PrParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.nic.pr", "pr", "error", "error.txt");
            var response = parser.Parse("whois.nic.pr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Error, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.pr/pr/error/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.pr", "pr", "not-found", "u34jedzcq.pr.txt");
            var response = parser.Parse("whois.nic.pr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.pr/pr/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.pr", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.pr", "pr", "found", "google.pr.txt");
            var response = parser.Parse("whois.nic.pr", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.pr/pr/found/01", response.TemplateName);

            Assert.Equal("google.pr", response.DomainName.ToString());

            Assert.Equal(new DateTime(2005, 09, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 09, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(8, response.FieldsParsed);
        }
    }
}
