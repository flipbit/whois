using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lv.Lv
{
    public class LvParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public LvParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.lv", "lv", "not_found.txt");
            var response = parser.Parse("whois.nic.lv", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.lv/lv/Found", response.TemplateName);

            Assert.Equal("u34jedzcq.lv", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("free", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.lv", "lv", "found.txt");
            var response = parser.Parse("whois.nic.lv", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.lv/lv/Found", response.TemplateName);

            Assert.Equal("google.lv", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
            Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
            Assert.Equal("+12083895740", response.Registrar.AbuseTelephoneNumber);


             // Registrant Details
            Assert.Equal("Google, Inc.", response.Registrant.Name);
            Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(1, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway, Mountain View, CA, 94043, USA", response.Registrant.Address[0]);


             // TechnicalContact Details
            Assert.Equal("+12083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+12083895799", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("active", response.DomainStatus[0]);

            Assert.Equal(18, response.FieldsParsed);
        }
    }
}
