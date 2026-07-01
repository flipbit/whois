using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Qa.Qa
{
    public class QaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public QaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.qa", "qa", "found.txt");
            var response = parser.Parse("whois.registry.qa", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.qa/qa/Found", response.TemplateName);

            Assert.Equal("qnb.com.qa", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Qatar Telecom (Qtel) Q. S. C", response.Registrar.Name);

             // Registrant Details
            Assert.Equal("QT40975", response.Registrant.RegistryId);
            Assert.Equal("DNS Administrator - Qtel Internet Services", response.Registrant.Name);


             // TechnicalContact Details
            Assert.Equal("QT40975", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Administrator - Qtel Internet Services", response.TechnicalContact.Name);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.qatarbank.com", response.NameServers[0]);
            Assert.Equal("ns2.qatarbank.com", response.NameServers[1]);
            Assert.Equal("ns3.qatarbank.com", response.NameServers[2]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("serverDeleteProhibited (Legacy)", response.DomainStatus[0]);
            Assert.Equal("serverRenewProhibited (Legacy)", response.DomainStatus[1]);
            Assert.Equal("serverTransferProhibited (Legacy)", response.DomainStatus[2]);

            Assert.Equal(13, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registry.qa", "qa", "not_found.txt");
            var response = parser.Parse("whois.registry.qa", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.qa/qa/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.registry.qa", "qa", "found_status_registered.txt");
            var response = parser.Parse("whois.registry.qa", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.qa/qa/Found", response.TemplateName);

            Assert.Equal("qtel.com.qa", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Qatar Telecom (Qtel) Q. S. C", response.Registrar.Name);


             // Registrant Details
            Assert.Equal("QT11734", response.Registrant.RegistryId);
            Assert.Equal("DNS Administrator - Qtel Internet Services", response.Registrant.Name);


             // TechnicalContact Details
            Assert.Equal("QT11734", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Administrator - Qtel Internet Services", response.TechnicalContact.Name);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.qtel.com.qa", response.NameServers[0]);
            Assert.Equal("ns2.qtel.com.qa", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(10, response.FieldsParsed);
        }
    }
}
