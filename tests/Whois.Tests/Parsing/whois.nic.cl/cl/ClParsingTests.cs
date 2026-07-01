using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cl.Cl
{
    public class ClParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ClParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.cl", "cl", "not_found.txt");
            var response = parser.Parse("whois.nic.cl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.cl/cl/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.cl", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.cl", "cl", "found.txt");
            var response = parser.Parse("whois.nic.cl", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.cl/cl/Found", response.TemplateName);

            Assert.Equal("google.cl", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Google Inc. Representada por NameAction Chile S.A. (ASESORIAS NAMEACTION CHILE LIMITADA)", response.Registrant.Name);

             // AdminContact Details
            Assert.Equal("Markmonitor Tech", response.AdminContact.Name);
            Assert.Equal("Markmonitor", response.AdminContact.Organization);


             // TechnicalContact Details
            Assert.Equal("Markmonitor Tech", response.TechnicalContact.Name);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);

            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns3.google.com", response.NameServers[0]);
            Assert.Equal("ns4.google.com", response.NameServers[1]);
            Assert.Equal("ns1.google.com", response.NameServers[2]);
            Assert.Equal("ns2.google.com", response.NameServers[3]);

            Assert.Equal(11, response.FieldsParsed);
        }
    }
}
