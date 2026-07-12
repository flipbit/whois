using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Usp.Ac.Fj.Fj
{
    public class FjParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public FjParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.usp.ac.fj", "fj", "not-found", "not_found.txt");
            var response = parser.Parse("whois.usp.ac.fj", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.usp.ac.fj/fj/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.fj", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.usp.ac.fj", "fj", "found", "found.txt");
            var response = parser.Parse("whois.usp.ac.fj", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.usp.ac.fj/fj/found/01", response.TemplateName);

            Assert.Equal("google.com.fj", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(1, response.Registrant.Address.Count);
            Assert.Equal("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("Active", response.DomainStatus[0]);

            Assert.Equal(7, response.FieldsParsed);
        }
    }
}
