using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cdmon.Com.Com
{
    public class ComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.cdmon.com", "com", "found.txt");
            var response = parser.Parse("whois.cdmon.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("cdmon.com", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("10DENCEHISPAHARD, S.L", response.Registrar.Name);
            Assert.Equal("1403", response.Registrar.IanaId);
            Assert.Equal("https://www.cdmon.com", response.Registrar.Url);
            Assert.Equal("whois.cdmon.com", response.Registrar.WhoisServer.Value);
            Assert.Equal("abuse@cdmon.com", response.Registrar.AbuseEmail);
            Assert.Equal("+34.935677577", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2009, 12, 16, 11, 40, 44, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2001, 08, 12, 15, 02, 57, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2024, 08, 12, 15, 02, 53, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("10dencehispahard,s.l.", response.Registrant.Name);
            Assert.Equal("10dencehispahard,s.l.", response.Registrant.Organization);
            Assert.Equal("+34.902364138", response.Registrant.TelephoneNumber);
            Assert.Equal("info@cdmon.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Girona 81-83 local 6", response.Registrant.Address[0]);
            Assert.Equal("Malgrat de Mar", response.Registrant.Address[1]);
            Assert.Equal("08380", response.Registrant.Address[2]);
            Assert.Equal("ES", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("10dencehispahard,s.l.", response.AdminContact.Name);
            Assert.Equal("10dencehispahard,s.l.", response.AdminContact.Organization);
            Assert.Equal("+34.902364138", response.AdminContact.TelephoneNumber);
            Assert.Equal("info@cdmon.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Girona 81-83 local 6", response.AdminContact.Address[0]);
            Assert.Equal("Malgrat de Mar", response.AdminContact.Address[1]);
            Assert.Equal("08380", response.AdminContact.Address[2]);
            Assert.Equal("ES", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("10dencehispahard,s.l.", response.TechnicalContact.Name);
            Assert.Equal("10dencehispahard,s.l.", response.TechnicalContact.Organization);
            Assert.Equal("+34.902364138", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("info@cdmon.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Girona 81-83 local 6", response.TechnicalContact.Address[0]);
            Assert.Equal("Malgrat de Mar", response.TechnicalContact.Address[1]);
            Assert.Equal("08380", response.TechnicalContact.Address[2]);
            Assert.Equal("ES", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns2.cdmon.es", response.NameServers[0]);
            Assert.Equal("ns3.cdmon.es", response.NameServers[1]);
            Assert.Equal("ns1.cdmon.es", response.NameServers[2]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(42, response.FieldsParsed);
        }
    }
}
