using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Om.Om
{
    public class OmParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public OmParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "not-found", "not_found.txt");
            var response = parser.Parse("whois.registry.om", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.om/om/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "found", "found.txt");
            var response = parser.Parse("whois.registry.om", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.om/om/found/01", response.TemplateName);

            Assert.Equal("rop.gov.om", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Oman Telecommunication Company", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 10, 06, 18, 20, 12, 000, DateTimeKind.Utc), response.Updated);

             // Registrant Details
            Assert.Equal("10084244", response.Registrant.RegistryId);
            Assert.Equal("Nasser Said Al Daree", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(2, response.Registrant.Address.Count);
            Assert.Equal("Mina Al Fahal", response.Registrant.Address[0]);
            Assert.Equal("om", response.Registrant.Address[1]);


             // TechnicalContact Details
            Assert.Equal("10084244", response.TechnicalContact.RegistryId);
            Assert.Equal("Nasser Said Al Daree", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(2, response.TechnicalContact.Address.Count);
            Assert.Equal("Mina Al Fahal", response.TechnicalContact.Address[0]);
            Assert.Equal("om", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns3.omantel.net.om", response.NameServers[0]);
            Assert.Equal("ns1.omantel.net.om", response.NameServers[1]);
            Assert.Equal("ns2.omantel.net.om", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.registry.om", "om", "reserved", "reserved.txt");
            var response = parser.Parse("whois.registry.om", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.registry.om/om/reserved/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }
    }
}
