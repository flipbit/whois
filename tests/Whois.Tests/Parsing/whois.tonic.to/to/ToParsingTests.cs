using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tonic.To.To
{
    public class ToParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ToParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tonic.to", "to", "not_found.txt");
            var response = parser.Parse("whois.tonic.to", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tonic.to/to/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tonic.to", "to", "found.txt");
            var response = parser.Parse("whois.tonic.to", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.tonic.to/to/Found", response.TemplateName);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns-1.myphotoalbum.com", response.NameServers[0]);
            Assert.Equal("ns-2.myphotoalbum.com", response.NameServers[1]);

            Assert.Equal(3, response.FieldsParsed);
        }
    }
}
