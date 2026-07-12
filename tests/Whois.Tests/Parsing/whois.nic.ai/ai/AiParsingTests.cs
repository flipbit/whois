using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ai.Ai
{
    public class AiParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AiParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.ai", "ai", "not-found", "u34jedzcq.ai.txt");
            var response = parser.Parse("whois.nic.ai", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ai/ai/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.ai", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ai", "ai", "found", "google.ai.txt");
            var response = parser.Parse("whois.nic.ai", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.ai/ai/found/01", response.TemplateName);

            Assert.Equal("google.ai", response.DomainName.ToString());

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("DNS Admin", response.AdminContact.Name);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View", response.AdminContact.Address[1]);
            Assert.Equal("CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("CCOPSBilling", response.BillingContact.Name);
            Assert.Equal("MarkMonitor", response.BillingContact.Organization);
            Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("391 N. Ancestor Pl", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("ID", response.BillingContact.Address[2]);
            Assert.Equal("83704", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("Administrator, Domain", response.TechnicalContact.Name);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
            Assert.Equal("+1.2083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("391 N. Ancestor Pl", response.TechnicalContact.Address[0]);
            Assert.Equal("Boise", response.TechnicalContact.Address[1]);
            Assert.Equal("ID", response.TechnicalContact.Address[2]);
            Assert.Equal("83704", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(44, response.FieldsParsed);
        }
    }
}
