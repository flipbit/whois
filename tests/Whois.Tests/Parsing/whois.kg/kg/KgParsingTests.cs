using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kg.Kg
{
    public class KgParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public KgParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.kg", "kg", "not_found.txt");
            var response = parser.Parse("whois.kg", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.kg/kg/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.kg", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.kg", "kg", "found.txt");
            var response = parser.Parse("whois.kg", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.kg/kg/Found", response.TemplateName);

            Assert.Equal("google.kg", response.DomainName.ToString());

            Assert.Equal(new DateTime(2010, 04, 19, 21, 47, 14, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 02, 10, 09, 42, 42, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 03, 30, 23, 59, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.Equal("8386-KG", response.AdminContact.RegistryId);
            Assert.Equal("Google Inc.", response.AdminContact.Name);
            Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(1, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);


             // BillingContact Details
            Assert.Equal("5935-KG", response.BillingContact.RegistryId);
            Assert.Equal("Markmonitor", response.BillingContact.Name);
            Assert.Equal("+12083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("+12083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(1, response.BillingContact.Address.Count);
            Assert.Equal("391 N Ancestor Place Boise, ID 83704", response.BillingContact.Address[0]);


             // TechnicalContact Details
            Assert.Equal("5935-KG", response.TechnicalContact.RegistryId);
            Assert.Equal("Markmonitor", response.TechnicalContact.Name);
            Assert.Equal("+12083895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+12083895771", response.TechnicalContact.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(1, response.TechnicalContact.Address.Count);
            Assert.Equal("391 N Ancestor Place Boise, ID 83704", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns4.google.com", response.NameServers[2]);

            Assert.Equal(26, response.FieldsParsed);
        }
    }
}
