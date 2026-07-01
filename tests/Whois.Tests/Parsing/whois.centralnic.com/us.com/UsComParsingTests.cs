using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UsCom
{
    public class UsComParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UsComParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "us.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "us.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.centralnic.com/Found", response.TemplateName);

            Assert.Equal("college.us.com", response.DomainName.ToString());
            Assert.Equal("CNIC-DO275307", response.RegistryDomainId);

            Assert.Equal(new DateTime(2012, 1, 16, 16, 27, 26, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2003, 10, 20, 10, 3, 28, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2014, 10, 20, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H1044037", response.Registrant.RegistryId);
            Assert.Equal("Vantage Media Corporation", response.Registrant.Name);
            Assert.Equal("+1.3102196200", response.Registrant.TelephoneNumber);
            Assert.Equal("domainadmin@vantagemedia.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(4, response.Registrant.Address.Count);
            Assert.Equal("2101 Rosecrans Ave.", response.Registrant.Address[0]);
            Assert.Equal("Suite 2000", response.Registrant.Address[1]);
            Assert.Equal("90245", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.Equal("H143205", response.AdminContact.RegistryId);
            Assert.Equal("Domain Administrator", response.AdminContact.Name);
            Assert.Equal("Vantage Media LLC", response.AdminContact.Organization);
            Assert.Equal("+1.3102196200", response.AdminContact.TelephoneNumber);
            Assert.Equal("domainadmin@vantagemedia.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("2101 Rosecrans Ave.", response.AdminContact.Address[0]);
            Assert.Equal("Suite 2000", response.AdminContact.Address[1]);
            Assert.Equal("90245", response.AdminContact.Address[2]);
            Assert.Equal("US", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("H143205", response.BillingContact.RegistryId);
            Assert.Equal("Domain Administrator", response.BillingContact.Name);
            Assert.Equal("Vantage Media LLC", response.BillingContact.Organization);
            Assert.Equal("+1.3102196200", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.8665897214", response.BillingContact.FaxNumber);
            Assert.Equal("domainadmin@vantagemedia.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(3, response.BillingContact.Address.Count);
            Assert.Equal("2101 Rosecrans Ave.", response.BillingContact.Address[0]);
            Assert.Equal("90245", response.BillingContact.Address[1]);
            Assert.Equal("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.Equal("H143205", response.TechnicalContact.RegistryId);
            Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
            Assert.Equal("Vantage Media LLC", response.TechnicalContact.Organization);
            Assert.Equal("+1.3102196200", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("domainadmin@vantagemedia.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(4, response.TechnicalContact.Address.Count);
            Assert.Equal("2101 Rosecrans Ave.", response.TechnicalContact.Address[0]);
            Assert.Equal("Suite 2000", response.TechnicalContact.Address[1]);
            Assert.Equal("90245", response.TechnicalContact.Address[2]);
            Assert.Equal("US", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.Equal(4, response.NameServers.Count);
            Assert.Equal("ns1.p17.dynect.net", response.NameServers[0]);
            Assert.Equal("ns2.p17.dynect.net", response.NameServers[1]);
            Assert.Equal("ns3.p17.dynect.net", response.NameServers[2]);
            Assert.Equal("ns4.p17.dynect.net", response.NameServers[3]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal("Unsigned", response.DnsSecStatus);
            Assert.Equal(47, response.FieldsParsed);
        }
    }
}
