using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Bo.Bo
{
    public class BoParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public BoParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.bo", "bo", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.bo", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.bo/bo/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.bo", "bo", "found", "found.txt");
            var response = parser.Parse("whois.nic.bo", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.bo/bo/found/01", response.TemplateName);

            Assert.Equal("google.bo", response.DomainName.ToString());

            Assert.Equal(new DateTime(2006, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc", response.Registrant.Name);
            Assert.Equal("Google Inc.", response.Registrant.Organization);
            Assert.Equal("16502530000", response.Registrant.TelephoneNumber);
            Assert.Equal("mail@nameaction.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("Estados Unidos de America", response.Registrant.Address[0]);
            Assert.Equal("Mountain View", response.Registrant.Address[1]);
            Assert.Equal("1600 Amphitheatre Parkway Mountain View", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("Domain Administrator", response.AdminContact.Name);
            Assert.Equal("MarkMonitor Inc.", response.AdminContact.Organization);
            Assert.Equal("12083895740", response.AdminContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Estados Unidos de America", response.AdminContact.Address[0]);
            Assert.Equal("Boise", response.AdminContact.Address[1]);
            Assert.Equal("391 N. Ancestor pl.", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("Domain Administrator", response.BillingContact.Name);
            Assert.Equal("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.Equal("12083895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("Estados Unidos de America", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("391 N. Ancestor pl.", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("MarkMonitor", response.TechnicalContact.Name);
            Assert.Equal("MarkMonitor", response.TechnicalContact.Organization);
            Assert.Equal("+1208389 5783", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("mail@nameaction.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("USA", response.TechnicalContact.Address[0]);
            Assert.Equal("Boise, Idaho  83704", response.TechnicalContact.Address[1]);
            Assert.Equal("391 N. Ancestor Place", response.TechnicalContact.Address[2]);


            Assert.Equal(32, response.FieldsParsed);
        }
    }
}
