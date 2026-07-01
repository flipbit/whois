using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Gov.Za.GovZa
{
    public class GovZaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public GovZaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.gov.za", "gov.za", "not_found.txt");
            var response = parser.Parse("whois.gov.za", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.gov.za/gov.za/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.gov.za", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.gov.za", "gov.za", "found.txt");
            var response = parser.Parse("whois.gov.za", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.gov.za/gov.za/Found", response.TemplateName);

            Assert.Equal("dha.gov.za", response.DomainName.ToString());

            Assert.Equal(new DateTime(2012, 09, 03, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("Department of Home Affairs", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(2, response.Registrant.Address.Count);
            Assert.Equal("Private Bag x114,Pretoria,", response.Registrant.Address[0]);
            Assert.Equal("0001", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.Equal("Zakhele Khuzwayo", response.AdminContact.Name);
            Assert.Equal("Department of Home Affairs", response.AdminContact.Organization);
            Assert.Equal("zakhele.khuzwayo@dha.gov.za", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(2, response.AdminContact.Address.Count);
            Assert.Equal("Private Bag x114,0001,", response.AdminContact.Address[0]);
            Assert.Equal("Pretoria", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.Equal("David D. Sussens", response.TechnicalContact.Name);
            Assert.Equal("SITA", response.TechnicalContact.Organization);
            Assert.Equal("david.sussens@sita.co.za", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(2, response.TechnicalContact.Address.Count);
            Assert.Equal("Private Bag x114,Pretoria,", response.TechnicalContact.Address[0]);
            Assert.Equal("0001", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.Equal(1, response.NameServers.Count);
            Assert.Equal("ns1.dha.gov.za", response.NameServers[0]);

            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
