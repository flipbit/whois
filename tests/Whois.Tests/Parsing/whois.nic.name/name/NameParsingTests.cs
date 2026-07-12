using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Name.Name
{
    public class NameParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public NameParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.name", "name", "reserved", "reserved.txt");
            var response = parser.Parse("whois.nic.name", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.name/name/reserved/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.name", "name", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.name", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.name/name/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.name", response.DomainName.ToString());
            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.name", "name", "found", "found.txt");
            var response = parser.Parse("whois.nic.name", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.name/name/found/01", response.TemplateName);

            Assert.Equal("carletti.name", response.DomainName.ToString());
            Assert.Equal("2788515_DOMAIN_NAME-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("eNom, Inc.", response.Registrar.Name);

            Assert.Equal(new DateTime(2013, 11, 30, 18, 51, 55, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2006, 04, 19, 12, 22, 08, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 04, 19, 12, 22, 08, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("7903395_CONTACT_NAME-VRSN", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.Equal("10919759_CONTACT_NAME-VRSN", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.Equal("10919759_CONTACT_NAME-VRSN", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.Equal("10919759_CONTACT_NAME-VRSN", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.dnsimple.com", response.NameServers[0]);
            Assert.Equal("ns2.dnsimple.com", response.NameServers[1]);
            Assert.Equal("ns3.dnsimple.com", response.NameServers[2]);
            Assert.Equal("ns4.dnsimple.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

            Assert.Equal(16, response.FieldsParsed);
        }
    }
}
