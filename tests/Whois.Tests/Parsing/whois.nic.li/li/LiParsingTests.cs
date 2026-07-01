using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Li.Li
{
    public class LiParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public LiParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.li", "li", "not_found.txt");
            var response = parser.Parse("whois.nic.li", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.li/li/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.li", "li", "found.txt");
            var response = parser.Parse("whois.nic.li", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.li/li/Found", response.TemplateName);

            Assert.Equal("google.li", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Administrator Domain", response.Registrant.Address[0]);
            Assert.Equal("Amphitheatre Parkway 1600", response.Registrant.Address[1]);
            Assert.Equal("US-94043 Mountain View, CA", response.Registrant.Address[2]);
            Assert.Equal("United States", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.Equal("Google Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("DNS Admin", response.TechnicalContact.Address[0]);
            Assert.Equal("2400 E. Bayshore Pkwy", response.TechnicalContact.Address[1]);
            Assert.Equal("US-94043 Mountain View", response.TechnicalContact.Address[2]);
            Assert.Equal("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal("N", response.DnsSecStatus);
            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
