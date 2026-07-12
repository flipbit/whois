using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Pandi.Or.Id.Id
{
    public class IdParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public IdParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.pandi.or.id", "id", "not-found", "not_found.txt");
            var response = parser.Parse("whois.pandi.or.id", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.pandi.or.id", "id", "found", "google.co.id.txt");
            var response = parser.Parse("whois.pandi.or.id", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("google.co.id", response.DomainName.ToString());
            Assert.Equal("PANDI-DO246796", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("0274882257", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 09, 20, 23, 24, 51, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2004, 12, 18, 13, 33, 21, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 09, 01, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("0123459P2ZC", response.Registrant.RegistryId);
            Assert.Equal("Domain Administrator", response.Registrant.Name);
            Assert.Equal("PT Google Indonesia", response.Registrant.Organization);
            Assert.Equal("+62.2123584400", response.Registrant.TelephoneNumber);
            Assert.Equal("+62.2123584400", response.Registrant.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Menara BCA Grand Indonesia", response.Registrant.Address[0]);
            Assert.Equal("Regus Grand Indonesia", response.Registrant.Address[1]);
            Assert.Equal("Jakarta", response.Registrant.Address[2]);
            Assert.Equal("Jakarta", response.Registrant.Address[3]);
            Assert.Equal("10310", response.Registrant.Address[4]);
            Assert.Equal("ID", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.Equal("0123459P2ZC", response.AdminContact.RegistryId);
            Assert.Equal("Domain Administrator", response.AdminContact.Name);
            Assert.Equal("PT Google Indonesia", response.AdminContact.Organization);
            Assert.Equal("+62.2123584400", response.AdminContact.TelephoneNumber);
            Assert.Equal("+62.2123584400", response.AdminContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(6, response.AdminContact.Address.Count);
            Assert.Equal("Menara BCA Grand Indonesia", response.AdminContact.Address[0]);
            Assert.Equal("Regus Grand Indonesia", response.AdminContact.Address[1]);
            Assert.Equal("Jakarta", response.AdminContact.Address[2]);
            Assert.Equal("Jakarta", response.AdminContact.Address[3]);
            Assert.Equal("10310", response.AdminContact.Address[4]);
            Assert.Equal("ID", response.AdminContact.Address[5]);


             // BillingContact Details
            Assert.Equal("0120505a1pl", response.BillingContact.RegistryId);
            Assert.Equal("CCOPS Billing", response.BillingContact.Name);
            Assert.Equal("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.Equal("+1.2083895741", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("JL.Hang Kesturi KM 4 Kabil Indus", response.BillingContact.Address[0]);
            Assert.Equal("Boise", response.BillingContact.Address[1]);
            Assert.Equal("ID", response.BillingContact.Address[2]);
            Assert.Equal("83704", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("01234616RFG", response.TechnicalContact.RegistryId);
            Assert.Equal("DNS Admin", response.TechnicalContact.Name);
            Assert.Equal("Google Inc.", response.TechnicalContact.Organization);
            Assert.Equal("+1.65030000", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.65030001", response.TechnicalContact.FaxNumber);
            Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
            Assert.Equal("CA", response.TechnicalContact.Address[2]);
            Assert.Equal("94043", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.google.com", response.NameServers[0]);
            Assert.Equal("ns2.google.com", response.NameServers[1]);
            Assert.Equal("ns3.google.com", response.NameServers[2]);
            Assert.Equal("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(60, response.FieldsParsed);
        }
    }
}
