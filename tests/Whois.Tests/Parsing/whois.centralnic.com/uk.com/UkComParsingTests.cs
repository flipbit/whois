using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UkCom
{
    public class UkComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UkComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "uk.com", "not-found", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "uk.com", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("history.uk.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO86293", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("E-VELOCITY LTD", response.Registrar.Name);
            Assert.Equal("http://www.e-velocity.co.uk/", response.Registrar.Url);
            Assert.Equal("01273 684969", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 9, 3, 10, 36, 47, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2001, 8, 31, 11, 50, 57, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 8, 31, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H1045821", response.Registrant.RegistryId);
            Assert.Equal("Mr. Ray Hatley", response.Registrant.Name);
            Assert.Equal("+44.1584873633", response.Registrant.TelephoneNumber);
            Assert.Equal("ray@hatley.co.uk", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Tallow House", response.Registrant.Address[0]);
            Assert.Equal("65-66 Lower Galdeford", response.Registrant.Address[1]);
            Assert.Equal("Ludlow", response.Registrant.Address[2]);
            Assert.Equal("Shropshire", response.Registrant.Address[3]);
            Assert.Equal("SY8 1RU", response.Registrant.Address[4]);
            Assert.Equal("GB", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.Equal("H305798", response.AdminContact.RegistryId);
            Assert.Equal("Mr. Ray Hatley", response.AdminContact.Name);
            Assert.Equal("+44.1584873633", response.AdminContact.TelephoneNumber);
            Assert.Equal("ray@hatley.co.uk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("Tallow House", response.AdminContact.Address[0]);
            Assert.Equal("65-66 Lower Galdeford", response.AdminContact.Address[1]);
            Assert.Equal("Ludlow", response.AdminContact.Address[2]);
            Assert.Equal("Shropshire", response.AdminContact.Address[3]);
            Assert.Equal("SY8 1RU", response.AdminContact.Address[4]);
            Assert.Equal("GB", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("H78362", response.TechnicalContact.RegistryId);
            Assert.Equal("Mr Simon Williams", response.TechnicalContact.Name);
            Assert.Equal("E-VELOCITY LTD", response.TechnicalContact.Organization);
            Assert.Equal("+44.1273684969", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("simon@e-velocity.co.uk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("P.O Box 3295", response.TechnicalContact.Address[0]);
            Assert.Equal("Brighton", response.TechnicalContact.Address[1]);
            Assert.Equal("BN50 9EY", response.TechnicalContact.Address[2]);
            Assert.Equal("GB", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns37.eukdns.com", response.NameServers[0]);
            Assert.Equal("ns38.eukdns.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(42, response.FieldsParsed);
        }
    }
}
