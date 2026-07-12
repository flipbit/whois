using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.GbNet
{
    public class GbNetParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public GbNetParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "gb.net", "not-found", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "gb.net", "found", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

            Assert.Equal("hotel.gb.net", response.DomainName.ToString());
            Assert.Equal("CNIC-DO1423750", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Gandi SAS", response.Registrar.Name);
            Assert.Equal("http://www.gandi.net/", response.Registrar.Url);
            Assert.Equal("+33 1 7039 3740", response.Registrar.AbuseTelephoneNumber);

            Assert.Equal(new DateTime(2013, 8, 30, 12, 42, 9, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2013, 8, 25, 12, 36, 24, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 8, 25, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("R1149-GANDI-PRYP", response.Registrant.RegistryId);
            Assert.Equal("Heinz Pierre Roeser", response.Registrant.Name);
            Assert.Equal("Roevertrieb", response.Registrant.Organization);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("Friedensstr. 77", response.Registrant.Address[0]);
            Assert.Equal("Grevenbroich", response.Registrant.Address[1]);
            Assert.Equal("41517", response.Registrant.Address[2]);
            Assert.Equal("DE", response.Registrant.Address[3]);

            Assert.Equal("+49.218145077", response.Registrant.TelephoneNumber);
            Assert.Equal("roevertrieb@aol.com", response.Registrant.Email);


             // AdminContact Details
            Assert.Equal("R1149-GANDI-PRYP", response.AdminContact.RegistryId);
            Assert.Equal("Heinz Pierre Roeser", response.AdminContact.Name);
            Assert.Equal("Roevertrieb", response.AdminContact.Organization);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("Friedensstr. 77", response.AdminContact.Address[0]);
            Assert.Equal("Grevenbroich", response.AdminContact.Address[1]);
            Assert.Equal("41517", response.AdminContact.Address[2]);
            Assert.Equal("DE", response.AdminContact.Address[3]);

            Assert.Equal("+49.218145077", response.AdminContact.TelephoneNumber);
            Assert.Equal("roevertrieb@aol.com", response.AdminContact.Email);


             // BillingContact Details
            Assert.Equal("R1149-GANDI-PRYP", response.BillingContact.RegistryId);
            Assert.Equal("Heinz Pierre Roeser", response.BillingContact.Name);
            Assert.Equal("Roevertrieb", response.BillingContact.Organization);

             // BillingContact Address
            Assert.Equal(4, response.BillingContact.Address.Count);
            Assert.Equal("Friedensstr. 77", response.BillingContact.Address[0]);
            Assert.Equal("Grevenbroich", response.BillingContact.Address[1]);
            Assert.Equal("41517", response.BillingContact.Address[2]);
            Assert.Equal("DE", response.BillingContact.Address[3]);

            Assert.Equal("+49.218145077", response.BillingContact.TelephoneNumber);
            Assert.Equal("roevertrieb@aol.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.Equal("R1149-GANDI-PRYP", response.TechnicalContact.RegistryId);
            Assert.Equal("Heinz Pierre Roeser", response.TechnicalContact.Name);
            Assert.Equal("Roevertrieb", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("Friedensstr. 77", response.TechnicalContact.Address[0]);
            Assert.Equal("Grevenbroich", response.TechnicalContact.Address[1]);
            Assert.Equal("41517", response.TechnicalContact.Address[2]);
            Assert.Equal("DE", response.TechnicalContact.Address[3]);

            Assert.Equal("+49.218145077", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("roevertrieb@aol.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.Equal(3, response.NameServers.Count);
            Assert.Equal("b.dns.gandi.net", response.NameServers[0]);
            Assert.Equal("c.dns.gandi.net", response.NameServers[1]);
            Assert.Equal("a.dns.gandi.net", response.NameServers[2]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(52, response.FieldsParsed);
        }
    }
}
