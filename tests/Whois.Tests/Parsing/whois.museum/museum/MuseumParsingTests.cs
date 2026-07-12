using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Museum.Museum
{
    public class MuseumParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public MuseumParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.museum", "museum", "not-found", "not_found.txt");
            var response = parser.Parse("whois.museum", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.museum/museum/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.museum", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.museum", "museum", "found", "found.txt");
            var response = parser.Parse("whois.museum", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("musedoma.museum", response.DomainName.ToString());
            Assert.Equal("D778-MUSEUM", response.RegistryDomainId);


             // Registrant Details
            Assert.Equal("AC727-MUSEUM", response.Registrant.RegistryId);
            Assert.Equal("n/a", response.Registrant.Name);
            Assert.Equal("Museum Domain Management Association", response.Registrant.Organization);
            Assert.Equal("ck@nrm.se", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Frescativaegen 40", response.Registrant.Address[0]);
            Assert.Equal("Stockholm", response.Registrant.Address[1]);
            Assert.Equal("104 05", response.Registrant.Address[2]);
            Assert.Equal("SE", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("C728-MUSEUM", response.AdminContact.RegistryId);
            Assert.Equal("Cary Karp", response.AdminContact.Name);
            Assert.Equal("Museum Domain Management Association", response.AdminContact.Organization);
            Assert.Equal("ck@nic.museum", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Frescativaegen 40", response.AdminContact.Address[0]);
            Assert.Equal("Stockholm", response.AdminContact.Address[1]);
            Assert.Equal("104 05", response.AdminContact.Address[2]);
            Assert.Equal("SE", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("C728-MUSEUM", response.BillingContact.RegistryId);
            Assert.Equal("Cary Karp", response.BillingContact.Name);
            Assert.Equal("Museum Domain Management Association", response.BillingContact.Organization);
            Assert.Equal("ck@nic.museum", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Frescativaegen 40", response.BillingContact.Address[0]);
            Assert.Equal("Stockholm", response.BillingContact.Address[1]);
            Assert.Equal("104 05", response.BillingContact.Address[2]);
            Assert.Equal("SE", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("C728-MUSEUM", response.TechnicalContact.RegistryId);
            Assert.Equal("Cary Karp", response.TechnicalContact.Name);
            Assert.Equal("Museum Domain Management Association", response.TechnicalContact.Organization);
            Assert.Equal("ck@nic.museum", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Frescativaegen 40", response.TechnicalContact.Address[0]);
            Assert.Equal("Stockholm", response.TechnicalContact.Address[1]);
            Assert.Equal("104 05", response.TechnicalContact.Address[2]);
            Assert.Equal("SE", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("nic.frd.se", response.NameServers[0]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(37, response.FieldsParsed);
        }
    }
}
