using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Je.Je
{
    public class JeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public JeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.je", "je", "not-found", "not_found.txt");
            var response = parser.Parse("whois.je", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.je/je/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.je", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Not Registered", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.je", "je", "found", "found.txt");
            var response = parser.Parse("whois.je", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.je/je/found/01", response.TemplateName);

            Assert.Equal("google.je", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

            Assert.Equal(new DateTime(2002, 10, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns4.google.com", response.NameServers[2]);
            Assert.Equal("ns3.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Active", response.DomainStatus[0]);

            Assert.Equal(12, response.FieldsParsed);
        }
    }
}
