using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dotpostregistry.Net.Post
{
    public class PostParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public PostParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dotpostregistry.net", "post", "not_found.txt");
            var response = parser.Parse("whois.dotpostregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/NotFound001", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dotpostregistry.net", "post", "found.txt");
            var response = parser.Parse("whois.dotpostregistry.net", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/Found001", response.TemplateName);

            Assert.Equal("posteitaliane.post", response.DomainName.ToString());
            Assert.Equal("D19482-POST", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Universal Postal Union (R4947-POST)", response.Registrar.Name);

            Assert.Equal(new DateTime(2012, 09, 21, 12, 07, 40, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2012, 09, 21, 12, 03, 07, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 09, 21, 12, 03, 07, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("ITPI30001", response.Registrant.RegistryId);
            Assert.Equal("Poste Italiane", response.Registrant.Name);
            Assert.Equal("Poste Italiane", response.Registrant.Organization);
            Assert.Equal("+39.0659581", response.Registrant.TelephoneNumber);
            Assert.Equal("+39.065942298", response.Registrant.FaxNumber);
            Assert.Equal("info@poste.it", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Viale Europa 190", response.Registrant.Address[0]);
            Assert.Equal("Rome", response.Registrant.Address[1]);
            Assert.Equal("00144", response.Registrant.Address[2]);
            Assert.Equal("IT", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("UPU_C1002", response.AdminContact.RegistryId);
            Assert.Equal("Giovanni Brardinoni", response.AdminContact.Name);
            Assert.Equal("Poste Italiane", response.AdminContact.Organization);
            Assert.Equal("+39.0659583671", response.AdminContact.TelephoneNumber);
            Assert.Equal("+39.0698688651", response.AdminContact.FaxNumber);
            Assert.Equal("Giovanni.Brardinoni@Postecom.it", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Viale Europa 175", response.AdminContact.Address[0]);
            Assert.Equal("Rome", response.AdminContact.Address[1]);
            Assert.Equal("00144", response.AdminContact.Address[2]);
            Assert.Equal("IT", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("UPU_C1003", response.BillingContact.RegistryId);
            Assert.Equal("Plautina Loreti", response.BillingContact.Name);
            Assert.Equal("Poste Italiane", response.BillingContact.Organization);
            Assert.Equal("+39.0659585699", response.BillingContact.TelephoneNumber);
            Assert.Equal("+39.0659589591", response.BillingContact.FaxNumber);
            Assert.Equal("loretip@posteitaliane.it", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Viale Europa 175", response.BillingContact.Address[0]);
            Assert.Equal("Rome", response.BillingContact.Address[1]);
            Assert.Equal("00144", response.BillingContact.Address[2]);
            Assert.Equal("IT", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.Equal("UPU_C1001", response.TechnicalContact.RegistryId);
            Assert.Equal("Andrea Speranza", response.TechnicalContact.Name);
            Assert.Equal("Poste Italiane", response.TechnicalContact.Organization);
            Assert.Equal("+39.0659583086", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+39.0659582032", response.TechnicalContact.FaxNumber);
            Assert.Equal("netsecurity@postecom.it", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Viale Europa 175", response.TechnicalContact.Address[0]);
            Assert.Equal("Rome", response.TechnicalContact.Address[1]);
            Assert.Equal("00144", response.TechnicalContact.Address[2]);
            Assert.Equal("IT", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("dns.poste.it", response.NameServers[0]);
            Assert.Equal("dns2.poste.it", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("TRANSFER PROHIBITED", response.DomainStatus[0]);

            Assert.Equal("Signed", response.DnsSecStatus);
            Assert.Equal(51, response.FieldsParsed);
        }
    }
}
