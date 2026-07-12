using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.College.College
{
    public class CollegeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CollegeParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.college", "college", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.college", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.college", "college", "found", "nic.college.txt");
            var response = parser.Parse("whois.nic.college", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/found/01", response.TemplateName);

            Assert.Equal("nic.college", response.DomainName.ToString());
            Assert.Equal("D1465621-CNIC", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("CentralNic Ltd", response.Registrar.Name);
            Assert.Equal("9999", response.Registrar.IanaId);
            Assert.Equal("http://www.centralnic.com/", response.Registrar.Url);
            Assert.Equal("whois.centralnic.com", response.Registrar.WhoisServer.Value);

            Assert.Equal(new DateTime(2014, 09, 12, 00, 15, 47, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2013, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 09, 11, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("H5178905", response.Registrant.RegistryId);
            Assert.Equal("Domain Administrator", response.Registrant.Name);
            Assert.Equal("XYZ.COM LLC", response.Registrant.Organization);
            Assert.Equal("+1.8009998422", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.7023578299", response.Registrant.FaxNumber);
            Assert.Equal("icann@xyz.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("2121 E Tropicana Ave Suite #2", response.Registrant.Address[0]);
            Assert.Equal("Las Vegas", response.Registrant.Address[1]);
            Assert.Equal("NV", response.Registrant.Address[2]);
            Assert.Equal("89119", response.Registrant.Address[3]);
            Assert.Equal("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("H5178905", response.AdminContact.RegistryId);
            Assert.Equal("Domain Administrator", response.AdminContact.Name);
            Assert.Equal("XYZ.COM LLC", response.AdminContact.Organization);
            Assert.Equal("+1.8009998422", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.7023578299", response.AdminContact.FaxNumber);
            Assert.Equal("icann@xyz.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("2121 E Tropicana Ave Suite #2", response.AdminContact.Address[0]);
            Assert.Equal("Las Vegas", response.AdminContact.Address[1]);
            Assert.Equal("NV", response.AdminContact.Address[2]);
            Assert.Equal("89119", response.AdminContact.Address[3]);
            Assert.Equal("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("H5178905", response.BillingContact.RegistryId);
            Assert.Equal("Domain Administrator", response.BillingContact.Name);
            Assert.Equal("XYZ.COM LLC", response.BillingContact.Organization);
            Assert.Equal("+1.8009998422", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.7023578299", response.BillingContact.FaxNumber);
            Assert.Equal("icann@xyz.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("2121 E Tropicana Ave Suite #2", response.BillingContact.Address[0]);
            Assert.Equal("Las Vegas", response.BillingContact.Address[1]);
            Assert.Equal("NV", response.BillingContact.Address[2]);
            Assert.Equal("89119", response.BillingContact.Address[3]);
            Assert.Equal("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("H5178905", response.TechnicalContact.RegistryId);
            Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
            Assert.Equal("XYZ.COM LLC", response.TechnicalContact.Organization);
            Assert.Equal("+1.8009998422", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.7023578299", response.TechnicalContact.FaxNumber);
            Assert.Equal("icann@xyz.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("2121 E Tropicana Ave Suite #2", response.TechnicalContact.Address[0]);
            Assert.Equal("Las Vegas", response.TechnicalContact.Address[1]);
            Assert.Equal("NV", response.TechnicalContact.Address[2]);
            Assert.Equal("89119", response.TechnicalContact.Address[3]);
            Assert.Equal("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns0.centralnic-dns.com", response.NameServers[0]);
            Assert.Equal("ns1.centralnic-dns.com", response.NameServers[1]);
            Assert.Equal("ns2.centralnic-dns.com", response.NameServers[2]);
            Assert.Equal("ns3.centralnic-dns.com", response.NameServers[3]);
            Assert.Equal("ns4.centralnic-dns.com", response.NameServers[4]);
            Assert.Equal("ns5.centralnic-dns.com", response.NameServers[5]);

            // Domain Status
            Assert.Equal(4, response.DomainStatus.Count);
            Assert.Equal("serverTransferProhibited", response.DomainStatus[0]);
            Assert.Equal("serverUpdateProhibited", response.DomainStatus[1]);
            Assert.Equal("serverDeleteProhibited", response.DomainStatus[2]);
            Assert.Equal("serverRenewProhibited", response.DomainStatus[3]);

            Assert.Equal("unsigned", response.DnsSecStatus);
            Assert.Equal(65, response.FieldsParsed);
        }
    }
}
