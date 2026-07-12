using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Isnic.Is.Is
{
    public class IsParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IsParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.isnic.is", "is", "not-found", "not_found.txt");
            var response = parser.Parse("whois.isnic.is", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.isnic.is/is/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.is", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.isnic.is", "is", "found", "found.txt");
            var response = parser.Parse("whois.isnic.is", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/04", response.TemplateName);

            Assert.Equal("google.is", response.DomainName.ToString());

            Assert.Equal(new DateTime(2002, 05, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 05, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("Google Inc", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(3, response.Registrant.Address.Count);
            Assert.Equal("1600 Ampitheatre Parkway", response.Registrant.Address[0]);
            Assert.Equal("Mountain View, California 94043", response.Registrant.Address[1]);
            Assert.Equal("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.Equal("GI58-IS", response.AdminContact.RegistryId);
            Assert.Equal("Google Inc.", response.AdminContact.Organization);
            Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);
            Assert.Equal(new DateTime(2012, 10, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.Equal("Mountain View, CA 94043", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.Equal("MTC2-IS", response.BillingContact.RegistryId);
            Assert.Equal("Markmonitor Tech Contact", response.BillingContact.Name);
            Assert.Equal("+1 208 3895740", response.BillingContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.BillingContact.Email);
            Assert.Equal(new DateTime(2004, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.BillingContact.Created);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("391 N. Ancestor Pl.", response.BillingContact.Address[0]);
            Assert.Equal("Boise, ID 83704", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("MTC2-IS", response.TechnicalContact.RegistryId);
            Assert.Equal("Markmonitor Tech Contact", response.TechnicalContact.Name);
            Assert.Equal("+1 208 3895740", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);
            Assert.Equal(new DateTime(2004, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("391 N. Ancestor Pl.", response.TechnicalContact.Address[0]);
            Assert.Equal("Boise, ID 83704", response.TechnicalContact.Address[1]);
            Assert.Equal("US", response.TechnicalContact.Address[2]);


             // ZoneContact Details
            Assert.Equal("AG49-IS", response.ZoneContact.RegistryId);
            Assert.Equal("Amit Garg", response.ZoneContact.Name);
            Assert.Equal("+1 650 3300100", response.ZoneContact.TelephoneNumber);
            Assert.Equal("+1 650 6188571", response.ZoneContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.ZoneContact.Email);
            Assert.Equal(new DateTime(2004, 10, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.ZoneContact.Created);

             // ZoneContact Address
            Assert.Equal(4, response.ZoneContact.Address.Count);
            Assert.Equal("Google Inc.", response.ZoneContact.Address[0]);
            Assert.Equal("1600 Amphitheatre Parkway", response.ZoneContact.Address[1]);
            Assert.Equal("Mountain View, CA 94043", response.ZoneContact.Address[2]);
            Assert.Equal("US", response.ZoneContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);

            Assert.Equal(39, response.FieldsParsed);
        }
    }
}
