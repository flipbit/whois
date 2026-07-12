using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Za.Org.ZaOrg
{
    public class ZaOrgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ZaOrgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.za.org", "za.org", "not-found", "not_found.txt");
            var response = parser.Parse("whois.za.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.za.org/za.org/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.za.org", response.DomainName.ToString());
            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.za.org", "za.org", "found", "found.txt");
            var response = parser.Parse("whois.za.org", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.za.org/za.org/found/01", response.TemplateName);

            Assert.Equal("csa.za.org", response.DomainName.ToString());

            Assert.Equal(new DateTime(2009, 11, 22, 16, 01, 16, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("W&C Information Consultants CC", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("No 4 Botano Bldg", response.Registrant.Address[0]);
            Assert.Equal("Centurion", response.Registrant.Address[1]);
            Assert.Equal("0046", response.Registrant.Address[2]);
            Assert.Equal("South Africa", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("Willo van der Merwe", response.AdminContact.Name);
            Assert.Equal("+27 12 643 0288", response.AdminContact.TelephoneNumber);
            Assert.Equal("+27 12 643 0287", response.AdminContact.FaxNumber);
            Assert.Equal("hostmaster@wcic.co.za", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("W&C Information Consultants CC", response.AdminContact.Address[0]);
            Assert.Equal("No 4 Botano Bldg", response.AdminContact.Address[1]);
            Assert.Equal("Centurion", response.AdminContact.Address[2]);
            Assert.Equal("Gauteng", response.AdminContact.Address[3]);
            Assert.Equal("0046", response.AdminContact.Address[4]);
            Assert.Equal("South Africa", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("Willo van der Merwe", response.TechnicalContact.Name);
            Assert.Equal("+27 12 643 0288", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+27 12 643 0287", response.TechnicalContact.FaxNumber);
            Assert.Equal("hostmaster@wcic.co.za", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("W&C Information Consultants CC", response.TechnicalContact.Address[0]);
            Assert.Equal("No 4 Botano Bldg", response.TechnicalContact.Address[1]);
            Assert.Equal("Centurion", response.TechnicalContact.Address[2]);
            Assert.Equal("Gauteng", response.TechnicalContact.Address[3]);
            Assert.Equal("0046", response.TechnicalContact.Address[4]);
            Assert.Equal("South Africa", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("blade.wcic.co.za", response.NameServers[0]);
            Assert.Equal("sabertooth.wcic.co.za", response.NameServers[1]);
            Assert.Equal("ns2.iafrica.com", response.NameServers[2]);

            Assert.Equal(31, response.FieldsParsed);
        }
    }
}
