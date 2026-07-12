using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ax.Ax
{
    public class AxParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AxParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.ax", "ax", "not-found", "u34jedzcq.ax.txt");
            var response = parser.Parse("whois.ax", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(2, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ax/ax/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.ax", response.DomainName.ToString());
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ax", "ax", "found", "regeringen.ax.txt");
            var response = parser.Parse("whois.ax", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(11, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.ax/ax/found/01", response.TemplateName);

            Assert.Equal("regeringen.ax", response.DomainName.ToString());


            Assert.Equal(new DateTime(2006, 8, 3, 0, 0, 0), response.Registered);
            Assert.Equal("Ålands landskapsregering", response.Registrant.Name);
            Assert.Equal("0145076-7", response.Registrant.Organization);

            Assert.Equal(1, response.Registrant.Address.Count);
            Assert.Equal("AX", response.Registrant.Address[0]);


            Assert.Equal("IT-enheten", response.AdminContact.Name);

            Assert.Equal(2, response.AdminContact.Address.Count);
            Assert.Equal("PB 1060", response.AdminContact.Address[0]);
            Assert.Equal("22111  MARIEHAMN", response.AdminContact.Address[1]);

            Assert.Equal("itsupport@regeringen.ax", response.AdminContact.Email);


            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("ns.regeringen.ax", response.NameServers[0]);
        }
    }
}
