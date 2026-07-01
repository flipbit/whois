using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cd.Cd
{
    public class CdParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CdParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.cd", "cd", "not_found.txt");
            var response = parser.Parse("whois.nic.cd", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.cd/cd/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.cd", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Available", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.cd", "cd", "found.txt");
            var response = parser.Parse("whois.nic.cd", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.cd/cd/Found", response.TemplateName);

            Assert.Equal("google.cd", response.DomainName.ToString());
            Assert.Equal("5758-CD", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("MARKMONITOR", response.Registrar.Name);


            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(5, response.FieldsParsed);
        }
    }
}
