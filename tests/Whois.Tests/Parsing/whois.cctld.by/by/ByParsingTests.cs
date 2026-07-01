using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cctld.By.By
{
    public class ByParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ByParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cctld.by", "by", "not_found.txt");
            var response = parser.Parse("whois.cctld.by", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cctld.by/by/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cctld.by", "by", "found.txt");
            var response = parser.Parse("whois.cctld.by", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cctld.by/by/Found", response.TemplateName);

            Assert.Equal("active.by", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Active Technologies LLC", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 12, 16, 0, 0, 0), response.Updated);
            Assert.Equal(new DateTime(2003, 2, 2, 0, 0, 0), response.Registered);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.activeby.net", response.NameServers[0]);
            Assert.Equal("ns2.activeby.net", response.NameServers[1]);

            Assert.Equal(7, response.FieldsParsed);
        }
    }
}
