using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Za.Net.ZaNet
{
    public class ZaNetParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ZaNetParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.za.net", "za.net", "not-found", "u34jedzcq.za.net.txt");
            var response = parser.Parse("whois.za.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.za.net/za.net/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.za.net", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.za.net", "za.net", "found", "karnaugh.za.net.txt");
            var response = parser.Parse("whois.za.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.za.net/za.net/found/01", response.TemplateName);

            Assert.Equal("karnaugh.za.net", response.DomainName.ToString());

            Assert.Equal(new DateTime(2002, 03, 29, 22, 03, 53, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2002, 03, 29, 22, 03, 53, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2009, 11, 22, 16, 01, 16, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Colin Alston", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("11 Swales Crescent", response.Registrant.Address[0]);
            Assert.Equal("Pinetown", response.Registrant.Address[1]);
            Assert.Equal("3610", response.Registrant.Address[2]);
            Assert.Equal("South Africa", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("Colin Alston", response.AdminContact.Name);
            Assert.Equal("7037634", response.AdminContact.TelephoneNumber);
            Assert.Equal("diskbox@yifan.net", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("DAC", response.AdminContact.Address[0]);
            Assert.Equal("11 Swales Crecent", response.AdminContact.Address[1]);
            Assert.Equal("Pinetown", response.AdminContact.Address[2]);
            Assert.Equal("KZN", response.AdminContact.Address[3]);
            Assert.Equal("3610", response.AdminContact.Address[4]);
            Assert.Equal("South Africa", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("Colin Alston", response.TechnicalContact.Name);
            Assert.Equal("7037634", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("diskbox@yifan.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("DAC", response.TechnicalContact.Address[0]);
            Assert.Equal("11 Swales Crecent", response.TechnicalContact.Address[1]);
            Assert.Equal("Pinetown", response.TechnicalContact.Address[2]);
            Assert.Equal("KZN", response.TechnicalContact.Address[3]);
            Assert.Equal("3610", response.TechnicalContact.Address[4]);
            Assert.Equal("South Africa", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns3.zoneedit.com", response.NameServers[0]);
            Assert.Equal("ns5.zoneedit.com", response.NameServers[1]);

            Assert.Equal(30, response.FieldsParsed);
        }
    }
}
