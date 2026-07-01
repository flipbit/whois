using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UsOrg
{
    public class UsOrgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UsOrgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "us.org", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }
    }
}
