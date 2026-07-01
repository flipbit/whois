using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tld.Sy.Sy
{
    public class SyParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public SyParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.tld.sy", "sy", "not_found.txt");
            var response = parser.Parse("whois.tld.sy", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound005", response.TemplateName);

            Assert.Equal("u34jedzcq.sy", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.tld.sy", "sy", "found.txt");
            var response = parser.Parse("whois.tld.sy", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("tld.sy", response.DomainName.ToString());
            Assert.Equal("7-sy", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("nans", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 12, 02, 16, 01, 27, 664, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2017, 12, 01, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("6714-sy", response.Registrant.RegistryId);
            Assert.Equal("domain@tld.sy", response.Registrant.Email);


             // BillingContact Details
            Assert.Equal("6714-sy", response.BillingContact.RegistryId);
            Assert.Equal("domain@tld.sy", response.BillingContact.Email);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns4.tld.sy", response.NameServers[0]);
            Assert.Equal("ns3.tld.sy", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(14, response.FieldsParsed);
        }
    }
}
