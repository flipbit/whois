using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Pl.CoPl
{
    public class CoPlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CoPlParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.co.pl", "co.pl", "not-found", "not_found.txt");
            var response = parser.Parse("whois.co.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.co.pl/co.pl/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.co.pl", "co.pl", "found", "found.txt");
            var response = parser.Parse("whois.co.pl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.co.pl/co.pl/found/01", response.TemplateName);

            Assert.Equal("coco.co.pl", response.DomainName.ToString());

            Assert.Equal(new DateTime(2010, 06, 23, 09, 41, 50, DateTimeKind.Utc), response.Updated);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.co.pl", response.NameServers[0]);
            Assert.Equal("ns2.co.pl", response.NameServers[1]);

            Assert.Equal(5, response.FieldsParsed);
        }
    }
}
