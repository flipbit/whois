using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Mynic.My.My
{
    public class MyParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public MyParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.mynic.my", "my", "not_found.txt");
            var response = parser.Parse("whois.mynic.my", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.mynic.my/my/NotFound", response.TemplateName);

            Assert.Equal("u34jedzcq.my", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.mynic.my", "my", "found.txt");
            var response = parser.Parse("whois.mynic.my", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.mynic.my/my/Found", response.TemplateName);

            Assert.Equal("google.my", response.DomainName.ToString());

            Assert.Equal(new DateTime(2013, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2009, 05, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 05, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("INTEG4.ORG", response.Registrant.RegistryId);
            Assert.Equal("Integricity Corporation Sdn. Bhd.", response.Registrant.Name);
            Assert.Equal("(532745-U)", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("L1-46, First Floor, SStwo Mall", response.Registrant.Address[0]);
            Assert.Equal("40, Jalan SS2/72", response.Registrant.Address[1]);
            Assert.Equal("47300 Petaling Jaya", response.Registrant.Address[2]);
            Assert.Equal("Selangor", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("ALEXLAM3.CON", response.AdminContact.RegistryId);
            Assert.Equal("Network Admin Team", response.AdminContact.Name);
            Assert.Equal("Integricity Corporation Sdn. Bhd.", response.AdminContact.Organization);
            Assert.Equal("603-79570700", response.AdminContact.TelephoneNumber);
            Assert.Equal("603-79572700", response.AdminContact.FaxNumber);
            Assert.Equal("domain@fatservers.my", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("L1-46, First Floor, SStwo Mall", response.AdminContact.Address[0]);
            Assert.Equal("40, Jalan SS2/72", response.AdminContact.Address[1]);
            Assert.Equal("47300 Petaling Jaya", response.AdminContact.Address[2]);
            Assert.Equal("Selangor", response.AdminContact.Address[3]);
            Assert.Equal("Malaysia", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("ALEXLAM3.CON", response.BillingContact.RegistryId);
            Assert.Equal("Network Admin Team", response.BillingContact.Name);
            Assert.Equal("Integricity Corporation Sdn. Bhd.", response.BillingContact.Organization);
            Assert.Equal("603-79570700", response.BillingContact.TelephoneNumber);
            Assert.Equal("603-79572700", response.BillingContact.FaxNumber);
            Assert.Equal("domain@fatservers.my", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("L1-46, First Floor, SStwo Mall", response.BillingContact.Address[0]);
            Assert.Equal("40, Jalan SS2/72", response.BillingContact.Address[1]);
            Assert.Equal("47300 Petaling Jaya", response.BillingContact.Address[2]);
            Assert.Equal("Selangor", response.BillingContact.Address[3]);
            Assert.Equal("Malaysia", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("ALEXLAM3.CON", response.TechnicalContact.RegistryId);
            Assert.Equal("Network Admin Team", response.TechnicalContact.Name);
            Assert.Equal("Integricity Corporation Sdn. Bhd.", response.TechnicalContact.Organization);
            Assert.Equal("603-79570700", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("603-79572700", response.TechnicalContact.FaxNumber);
            Assert.Equal("domain@fatservers.my", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("L1-46, First Floor, SStwo Mall", response.TechnicalContact.Address[0]);
            Assert.Equal("40, Jalan SS2/72", response.TechnicalContact.Address[1]);
            Assert.Equal("47300 Petaling Jaya", response.TechnicalContact.Address[2]);
            Assert.Equal("Selangor", response.TechnicalContact.Address[3]);
            Assert.Equal("Malaysia", response.TechnicalContact.Address[4]);


            Assert.Equal(45, response.FieldsParsed);
        }
    }
}
