using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Org.Whois.Registry.Net.Za.OrgZa
{
    public class OrgZaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public OrgZaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("org-whois.registry.net.za", "org.za", "not-found", "not_found.txt");
            var response = parser.Parse("org-whois.registry.net.za", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);
            
            Assert.Equal(2, response.FieldsParsed);
            Assert.Equal(0, response.ParsingErrors);

            Assert.Equal("nosuchdomain.org.za", response.DomainName.ToString());
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("org-whois.registry.net.za", "org.za", "found", "found.txt");
            var response = parser.Parse("org-whois.registry.net.za", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("org-whois.registry.net.za/org.za/found/01", response.TemplateName);

            Assert.Equal("joburg.org.za", response.DomainName.ToString());
            Assert.Equal("dom_8VP-9999", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("ZA Central Registry", response.Registrar.Name);
            Assert.Equal("org-whois2.registry.net.za", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2015, 2, 5, 8, 45, 51, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(1997, 10, 3, 9, 46, 34, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2999, 12, 31, 21, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("jobuRant", response.Registrant.RegistryId);
            Assert.Equal("City of Johannesburg Metropolitan Municipality", response.Registrant.Name);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("P.O. Box 30757", response.Registrant.Address[0]);
            Assert.Equal("Braamfontein", response.Registrant.Address[1]);
            Assert.Equal("Gauteng", response.Registrant.Address[2]);
            Assert.Equal("2017", response.Registrant.Address[3]);
            Assert.Equal("ZA", response.Registrant.Address[4]);

            Assert.Equal("+27.110186314", response.Registrant.TelephoneNumber);
            Assert.Equal("+27.113819583", response.Registrant.FaxNumber);
            Assert.Equal("joelsonp@joburg.org.za", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("zacr-a0c0379446", response.AdminContact.RegistryId);
            Assert.Equal("Joelson Pholoha", response.AdminContact.Name);

             // AdminContact Address
            Assert.Equal(3, response.AdminContact.Address.Count);
            Assert.Equal("Private Bag X10013, Sandton, 2146", response.AdminContact.Address[0]);
            Assert.Equal("-", response.AdminContact.Address[1]);
            Assert.Equal("--", response.AdminContact.Address[2]);

            Assert.Equal("+27.110186314", response.AdminContact.TelephoneNumber);
            Assert.Equal("+27.113819583", response.AdminContact.FaxNumber);
            Assert.Equal("Joelsonp@Joburg.org.za", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("zacr-07de5cca59", response.BillingContact.RegistryId);

             // BillingContact Address
            Assert.Equal(2, response.BillingContact.Address.Count);
            Assert.Equal("-", response.BillingContact.Address[0]);
            Assert.Equal("--", response.BillingContact.Address[1]);

             // TechnicalContact Details
            Assert.Equal("zacr-71fff5bce2", response.TechnicalContact.RegistryId);
            Assert.Equal("Eben Jacobs", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.Equal(3, response.TechnicalContact.Address.Count);
            Assert.Equal("Accounts Payable, Vida Building, Kabelweg 57, 1014 BA Amsterdam", response.TechnicalContact.Address[0]);
            Assert.Equal("-", response.TechnicalContact.Address[1]);
            Assert.Equal("--", response.TechnicalContact.Address[2]);

            Assert.Equal("+27.110186314", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+27.113819583", response.TechnicalContact.FaxNumber);
            Assert.Equal("ebenj@joburg.org.za", response.TechnicalContact.Email);

            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("demeter.is.co.za", response.NameServers[0]);
            Assert.Equal("jupiter.is.co.za", response.NameServers[1]);
            Assert.Equal("titan.is.co.za", response.NameServers[2]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(45, response.FieldsParsed);
        }
    }
}
