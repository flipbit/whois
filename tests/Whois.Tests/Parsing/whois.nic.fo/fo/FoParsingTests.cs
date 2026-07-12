using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fo.Fo
{
    public class FoParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public FoParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.fo", "fo", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.fo", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.fo/fo/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.fo", "fo", "found", "found.txt");
            var response = parser.Parse("whois.nic.fo", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.fo/fo/found/01", response.TemplateName);

            Assert.Equal("nic.fo", response.DomainName.ToString());

            Assert.Equal(new DateTime(2011, 07, 12, 12, 52, 57, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2010, 06, 03, 03, 34, 05, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 01, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("ID005359", response.Registrant.RegistryId);
            Assert.Equal("FO-umsitingin", response.Registrant.Name);
            Assert.Equal(new DateTime(2010, 07, 21, 19, 11, 55, 000, DateTimeKind.Utc), response.Registrant.Created);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Hoydalsvegur 19, Postboks 1255", response.Registrant.Address[0]);
            Assert.Equal("Torshavn", response.Registrant.Address[1]);
            Assert.Equal("110", response.Registrant.Address[2]);
            Assert.Equal("FO", response.Registrant.Address[3]);


             // TechnicalContact Details
            Assert.Equal("ID005359", response.TechnicalContact.RegistryId);
            Assert.Equal("FO-umsitingin", response.TechnicalContact.Name);
            Assert.Equal(new DateTime(2010, 07, 21, 19, 11, 55, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Hoydalsvegur 19, Postboks 1255", response.TechnicalContact.Address[0]);
            Assert.Equal("Torshavn", response.TechnicalContact.Address[1]);
            Assert.Equal("110", response.TechnicalContact.Address[2]);
            Assert.Equal("FO", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(5, response.NameServers.Count);
            Assert.Equal("ns1.gratisdns.dk", response.NameServers[0]);
            Assert.Equal("ns2.gratisdns.dk", response.NameServers[1]);
            Assert.Equal("ns3.gratisdns.dk", response.NameServers[2]);
            Assert.Equal("ns4.gratisdns.dk", response.NameServers[3]);
            Assert.Equal("ns5.gratisdns.dk", response.NameServers[4]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("paid and in zone", response.DomainStatus[0]);

            Assert.Equal(21, response.FieldsParsed);
        }
    }
}
