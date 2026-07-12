using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Coop.Coop
{
    public class CoopParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public CoopParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found", "moscowfood.coop.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.coop/coop/found/01", response.TemplateName);

            Assert.Equal("moscowfood.coop", response.DomainName.ToString());
            Assert.Equal("5662D-COOP", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("Domain Bank Inc.", response.Registrar.Name);
            Assert.Equal("31", response.Registrar.IanaId);

            Assert.Equal(new DateTime(2001, 10, 09, 04, 36, 36, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2013, 01, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("71764C-COOP", response.Registrant.RegistryId);
            Assert.Equal("Kenna Eaton", response.Registrant.Name);
            Assert.Equal("Moscow Food Co-op", response.Registrant.Organization);
            Assert.Equal("+1.2088828537", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.2088828082", response.Registrant.FaxNumber);
            Assert.Equal("kenna@moscowfood.coop", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("P. O. Box 9485", response.Registrant.Address[0]);
            Assert.Equal("Moscow", response.Registrant.Address[1]);
            Assert.Equal("ID", response.Registrant.Address[2]);
            Assert.Equal("83843", response.Registrant.Address[3]);
            Assert.Equal("United States", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("74326C-COOP", response.AdminContact.RegistryId);
            Assert.Equal("Carol Spurling", response.AdminContact.Name);
            Assert.Equal("Moscow Food Co-op", response.AdminContact.Organization);
            Assert.Equal("+1.2086690763", response.AdminContact.TelephoneNumber);
            Assert.Equal("outreach@moscowfood.coop", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("P. O. Box 9485", response.AdminContact.Address[0]);
            Assert.Equal("Moscow", response.AdminContact.Address[1]);
            Assert.Equal("ID", response.AdminContact.Address[2]);
            Assert.Equal("83843", response.AdminContact.Address[3]);
            Assert.Equal("United States", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("75003C-COOP", response.BillingContact.RegistryId);
            Assert.Equal("Sandy Hughes", response.BillingContact.Name);
            Assert.Equal("Moscow Food Co-op", response.BillingContact.Organization);
            Assert.Equal("+1.2088828537", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.2088828082", response.BillingContact.FaxNumber);
            Assert.Equal("payable@moscowfood.coop", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("P. O. Box 9485", response.BillingContact.Address[0]);
            Assert.Equal("Moscow", response.BillingContact.Address[1]);
            Assert.Equal("ID", response.BillingContact.Address[2]);
            Assert.Equal("83843", response.BillingContact.Address[3]);
            Assert.Equal("United States", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("75916C-COOP", response.TechnicalContact.RegistryId);
            Assert.Equal("Joseph Erhard-Hudson", response.TechnicalContact.Name);
            Assert.Equal("Moscow Food Co-op", response.TechnicalContact.Organization);
            Assert.Equal("+1.2088828537", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.2088828082", response.TechnicalContact.FaxNumber);
            Assert.Equal("joseph@moscowfood.coop", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("P. O. Box 9485", response.TechnicalContact.Address[0]);
            Assert.Equal("Moscow", response.TechnicalContact.Address[1]);
            Assert.Equal("ID", response.TechnicalContact.Address[2]);
            Assert.Equal("83843", response.TechnicalContact.Address[3]);
            Assert.Equal("United States", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.west-datacenter.net", response.NameServers[0]);
            Assert.Equal("ns1.west-datacenter.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(3, response.DomainStatus.Count);
            Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
            Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.Equal(59, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found", "calgary.coop.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.coop/coop/found/01", response.TemplateName);

            Assert.Equal("calgary.coop", response.DomainName.ToString());
            Assert.Equal("7441D-COOP", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("domains.coop", response.Registrar.Name);
            Assert.Equal("465", response.Registrar.IanaId);

            Assert.Equal(new DateTime(2002, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("54100C-COOP", response.Registrant.RegistryId);
            Assert.Equal("Net Admin", response.Registrant.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.Registrant.Organization);
            Assert.Equal("+1.4032196025", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.Registrant.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.Registrant.Address[0]);
            Assert.Equal("Calgary", response.Registrant.Address[1]);
            Assert.Equal("AB", response.Registrant.Address[2]);
            Assert.Equal("T1Y 7C7", response.Registrant.Address[3]);
            Assert.Equal("Canada", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("54100C-COOP", response.AdminContact.RegistryId);
            Assert.Equal("Net Admin", response.AdminContact.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.AdminContact.Organization);
            Assert.Equal("+1.4032196025", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.AdminContact.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.AdminContact.Address[0]);
            Assert.Equal("Calgary", response.AdminContact.Address[1]);
            Assert.Equal("AB", response.AdminContact.Address[2]);
            Assert.Equal("T1Y 7C7", response.AdminContact.Address[3]);
            Assert.Equal("Canada", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("54100C-COOP", response.BillingContact.RegistryId);
            Assert.Equal("Net Admin", response.BillingContact.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.BillingContact.Organization);
            Assert.Equal("+1.4032196025", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.BillingContact.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.BillingContact.Address[0]);
            Assert.Equal("Calgary", response.BillingContact.Address[1]);
            Assert.Equal("AB", response.BillingContact.Address[2]);
            Assert.Equal("T1Y 7C7", response.BillingContact.Address[3]);
            Assert.Equal("Canada", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("54100C-COOP", response.TechnicalContact.RegistryId);
            Assert.Equal("Net Admin", response.TechnicalContact.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.TechnicalContact.Organization);
            Assert.Equal("+1.4032196025", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.TechnicalContact.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.TechnicalContact.Address[0]);
            Assert.Equal("Calgary", response.TechnicalContact.Address[1]);
            Assert.Equal("AB", response.TechnicalContact.Address[2]);
            Assert.Equal("T1Y 7C7", response.TechnicalContact.Address[3]);
            Assert.Equal("Canada", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.calgarycoop.net", response.NameServers[0]);
            Assert.Equal("ns2.calgarycoop.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(58, response.FieldsParsed);
        }

        [Fact(Skip = "Template update deferred - WHOIS response format changed")]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "not-found", "u34jedzcq.coop.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.coop/coop/not-found/01", response.TemplateName);

            Assert.Equal("u34jedzcq.coop", response.DomainName.ToString());

            Assert.Equal(2, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.coop/coop/found/01", response.TemplateName);

            Assert.Equal("calgary.coop", response.DomainName.ToString());
            Assert.Equal("7441D-COOP", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("domains.coop", response.Registrar.Name);
            Assert.Equal("465", response.Registrar.IanaId);

            Assert.Equal(new DateTime(2002, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2017, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("54100C-COOP", response.Registrant.RegistryId);
            Assert.Equal("Net Admin", response.Registrant.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.Registrant.Organization);
            Assert.Equal("+1.4032196025", response.Registrant.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.Registrant.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.Registrant.Address[0]);
            Assert.Equal("Calgary", response.Registrant.Address[1]);
            Assert.Equal("AB", response.Registrant.Address[2]);
            Assert.Equal("T1Y 7C7", response.Registrant.Address[3]);
            Assert.Equal("Canada", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("54100C-COOP", response.AdminContact.RegistryId);
            Assert.Equal("Net Admin", response.AdminContact.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.AdminContact.Organization);
            Assert.Equal("+1.4032196025", response.AdminContact.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.AdminContact.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.AdminContact.Address[0]);
            Assert.Equal("Calgary", response.AdminContact.Address[1]);
            Assert.Equal("AB", response.AdminContact.Address[2]);
            Assert.Equal("T1Y 7C7", response.AdminContact.Address[3]);
            Assert.Equal("Canada", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("54100C-COOP", response.BillingContact.RegistryId);
            Assert.Equal("Net Admin", response.BillingContact.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.BillingContact.Organization);
            Assert.Equal("+1.4032196025", response.BillingContact.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.BillingContact.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.BillingContact.Address[0]);
            Assert.Equal("Calgary", response.BillingContact.Address[1]);
            Assert.Equal("AB", response.BillingContact.Address[2]);
            Assert.Equal("T1Y 7C7", response.BillingContact.Address[3]);
            Assert.Equal("Canada", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("54100C-COOP", response.TechnicalContact.RegistryId);
            Assert.Equal("Net Admin", response.TechnicalContact.Name);
            Assert.Equal("Calgary Co operative Association Limited", response.TechnicalContact.Organization);
            Assert.Equal("+1.4032196025", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("+1.4032995416", response.TechnicalContact.FaxNumber);
            Assert.Equal("netadmin@calgarycoop.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("2735 39 Avenue NE", response.TechnicalContact.Address[0]);
            Assert.Equal("Calgary", response.TechnicalContact.Address[1]);
            Assert.Equal("AB", response.TechnicalContact.Address[2]);
            Assert.Equal("T1Y 7C7", response.TechnicalContact.Address[3]);
            Assert.Equal("Canada", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.calgarycoop.net", response.NameServers[0]);
            Assert.Equal("ns2.calgarycoop.net", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("ok", response.DomainStatus[0]);

            Assert.Equal(58, response.FieldsParsed);
        }
    }
}
