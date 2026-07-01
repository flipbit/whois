using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.As.As
{
    public class AsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.as", "as", "not_found.txt");
            var response = parser.Parse("whois.nic.as", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound001", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.as", "as", "found.txt");
            var response = parser.Parse("whois.nic.as", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.as/as/Found", response.TemplateName);

            Assert.Equal("google.as", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc. (http://www.markmonitor.com)", response.Registrar.Name);

            Assert.Equal(new DateTime(2000, 08, 02, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google, Inc.", response.Registrant.Name);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ST_CL_UPDATEPROHIBITED ST_CL_DELETEPROHIBITED ST_CL_TRANSFERPROHIBITED", response.DomainStatus[0]);

            Assert.Equal(10, response.FieldsParsed);
        }
    }
}
