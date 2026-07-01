using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Dz.Dz
{
    public class DzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public DzParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.dz", "dz", "not_found.txt");
            var response = parser.Parse("whois.nic.dz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.dz/dz/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.dz", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.dz", "dz", "found.txt");
            var response = parser.Parse("whois.nic.dz", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.dz/dz/Found", response.TemplateName);

            Assert.Equal("google.dz", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("cerist", response.Registrar.Name);

            Assert.Equal(new DateTime(2007, 01, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.Equal("GOOGLE LLC", response.Registrant.Name);


             // AdminContact Details
            Assert.Equal("Domain Administrator", response.AdminContact.Name);
            Assert.Equal("GOOGLE LLC", response.AdminContact.Organization);
            Assert.Equal("+16502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+16502530000", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway, Mountain View, CA 94043 US", response.AdminContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("Domain AdmDomain Administratorinistrator", response.TechnicalContact.Name);
            Assert.Equal("MARKMONITOR INC", response.TechnicalContact.Organization);
            Assert.Equal("+12083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+12083895771", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("391 N Ancestor Place Boise, ID 83704 US", response.TechnicalContact.Address[0]);


            Assert.Equal(17, response.FieldsParsed);
        }
    }
}
