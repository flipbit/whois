using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Monic.Mo.Mo
{
    public class MoParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public MoParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.monic.mo", "mo", "not_found.txt");
            var response = parser.Parse("whois.monic.mo", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.monic.mo/mo/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.mo", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.monic.mo", "mo", "found.txt");
            var response = parser.Parse("whois.monic.mo", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.monic.mo/mo/Found", response.TemplateName);

            Assert.Equal("umac.mo", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MONIC", response.Registrar.Name);
            Assert.Equal("whois.monic.mo", response.Registrar.WhoisServer.Value);

            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("umacsn1.umac.mo", response.NameServers[0]);
            Assert.Equal("umacsn2.umac.mo", response.NameServers[1]);

            Assert.Equal(6, response.FieldsParsed);
        }
    }
}
