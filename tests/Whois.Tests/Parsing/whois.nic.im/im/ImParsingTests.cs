using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Im.Im
{
    public class ImParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public ImParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.im", "im", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.im", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.im/im/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.im", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.im", "im", "found", "found.txt");
            var response = parser.Parse("whois.nic.im", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.im/im/found/01", response.TemplateName);

            Assert.Equal("google.im", response.DomainName.ToString());

            // Registrar Details
            Assert.Equal("Reseller - Mark Monitor", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 08, 03, 23, 59, 52, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Address", response.Registrant.Address[0]);
            Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[1]);
            Assert.Equal("Mountain View, CA", response.Registrant.Address[2]);
            Assert.Equal("94043", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("Google Inc. Domain Admin", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Address", response.AdminContact.Address[0]);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[1]);
            Assert.Equal("Mountain View, CA", response.AdminContact.Address[2]);
            Assert.Equal("94043", response.AdminContact.Address[3]);
            Assert.Equal("United States", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("Mr Domain Administrator", response.BillingContact.Name);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Address", response.BillingContact.Address[0]);
            Assert.Equal("Emerald Tech Center", response.BillingContact.Address[1]);
            Assert.Equal("391 N. Ancestor Pl", response.BillingContact.Address[2]);
            Assert.Equal("Boise, ID", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("Mr Domain Administrator", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("Address", response.TechnicalContact.Address[0]);
            Assert.Equal("Emerald Tech Center", response.TechnicalContact.Address[1]);
            Assert.Equal("391 N. Ancestor Pl", response.TechnicalContact.Address[2]);
            Assert.Equal("Boise, ID", response.TechnicalContact.Address[3]);
            Assert.Equal("83704", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            Assert.Equal(30, response.FieldsParsed);
        }
    }
}
