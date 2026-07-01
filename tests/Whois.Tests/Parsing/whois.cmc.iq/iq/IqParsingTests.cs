using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cmc.Iq.Iq
{
    public class IqParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IqParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cmc.iq", "iq", "not_found.txt");
            var response = parser.Parse("whois.cmc.iq", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cmc.iq/iq/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.iq", response.DomainName.ToString());

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("No Object Found", response.DomainStatus[0]);

            Assert.Equal(3, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cmc.iq", "iq", "found.txt");
            var response = parser.Parse("whois.cmc.iq", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.cmc.iq/iq/Found", response.TemplateName);

            Assert.Equal("google.iq", response.DomainName.ToString());
            Assert.Equal("895-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("CMC Registrar", response.Registrar.Name);
            Assert.Equal("whois.cmc.iq", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2013, 09, 29, 05, 19, 04, 997, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 10, 03, 21, 00, 00, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 10, 02, 21, 00, 00, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("1443-cmc", response.Registrant.RegistryId);
            Assert.Equal("Dr.akraym al-hak baker", response.Registrant.Name);
            Assert.Equal("+964.7901790160", response.Registrant.TelephoneNumber);
            Assert.Equal("bl-yoban@yahoo.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("al-yarmuk", response.Registrant.Address[0]);
            Assert.Equal("baghdad", response.Registrant.Address[1]);
            Assert.Equal("IQ", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("2640-cmc", response.AdminContact.RegistryId);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(23, response.FieldsParsed);
        }
    }
}
