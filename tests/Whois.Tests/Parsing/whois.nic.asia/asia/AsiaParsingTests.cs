using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Asia.Asia
{
    public class AsiaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public AsiaParsingTests()
        {

            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "found", "novalash.asia.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.asia/asia/found/01", response.TemplateName);

            Assert.Equal("novalash.asia", response.DomainName.ToString());
            Assert.Equal("D1032500-ASIA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("007Names, Inc. R94-ASIA (91)", response.Registrar.Name);

            Assert.Equal(new DateTime(2010, 10, 01, 03, 30, 34, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 10, 30, 22, 54, 15, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2012, 10, 30, 22, 54, 15, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("7AERFN4T4P", response.Registrant.RegistryId);
            Assert.Equal("Sophy Merszei", response.Registrant.Name);
            Assert.Equal("Novalash", response.Registrant.Organization);
            Assert.Equal("+1.8664301261", response.Registrant.TelephoneNumber);
            Assert.Equal("khickman@awsp.com", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("3701 W. Alabama", response.Registrant.Address[0]);
            Assert.Equal("Houston", response.Registrant.Address[1]);
            Assert.Equal("TX", response.Registrant.Address[2]);
            Assert.Equal("US", response.Registrant.Address[3]);
            Assert.Equal("77027", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("5MTMZMT3K1", response.AdminContact.RegistryId);
            Assert.Equal(":Sophy Merszei", response.AdminContact.Name);
            Assert.Equal("Novalash", response.AdminContact.Organization);
            Assert.Equal("+1.8664301261", response.AdminContact.TelephoneNumber);
            Assert.Equal("khickman@awsp.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(4, response.AdminContact.Address.Count);
            Assert.Equal("3701 W. Alabama", response.AdminContact.Address[0]);
            Assert.Equal("Houston", response.AdminContact.Address[1]);
            Assert.Equal("US", response.AdminContact.Address[2]);
            Assert.Equal("77027", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.Equal("5MTMZMT3K1", response.BillingContact.RegistryId);
            Assert.Equal("Sophy Merszei", response.BillingContact.Name);
            Assert.Equal("Novalash", response.BillingContact.Organization);
            Assert.Equal("+1.8664301261", response.BillingContact.TelephoneNumber);
            Assert.Equal("khickman@awsp.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("3701 W. Alabama", response.BillingContact.Address[0]);
            Assert.Equal("Houston", response.BillingContact.Address[1]);
            Assert.Equal("TX", response.BillingContact.Address[2]);
            Assert.Equal("US", response.BillingContact.Address[3]);
            Assert.Equal("77027", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("FR-11594d9eed91", response.TechnicalContact.RegistryId);
            Assert.Equal("Edward Lin", response.TechnicalContact.Name);
            Assert.Equal("EDM Enterprise Co., LTD", response.TechnicalContact.Organization);
            Assert.Equal("+886.425625115", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("doamina@yahoo.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("No. 10 Lane 241, Chung Shan Road", response.TechnicalContact.Address[0]);
            Assert.Equal("Shen Kang Hsiang", response.TechnicalContact.Address[1]);
            Assert.Equal("Taichung Hsien", response.TechnicalContact.Address[2]);
            Assert.Equal("TW", response.TechnicalContact.Address[3]);
            Assert.Equal("35000", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns2.rackspace.com", response.NameServers[0]);
            Assert.Equal("ns.raskspace.com", response.NameServers[1]);

            // Domain Status
            Assert.Equal(2, response.DomainStatus.Count);
            Assert.Equal("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);

            Assert.Equal(50, response.FieldsParsed);
        }

        [Fact]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "found", "cj7.asia.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.asia/asia/found/01", response.TemplateName);

            Assert.Equal("cj7.asia", response.DomainName.ToString());
            Assert.Equal("D93126-ASIA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("dotASIA R4-ASIA (9998)", response.Registrar.Name);

            Assert.Equal(new DateTime(2008, 03, 16, 04, 30, 25, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2010, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("FR-1158300cc88a", response.Registrant.RegistryId);
            Assert.Equal("Pioneer Domain (Temporary Delegation)", response.Registrant.Name);
            Assert.Equal("DotAsia Organisation", response.Registrant.Organization);
            Assert.Equal("+852.35202635", response.Registrant.TelephoneNumber);
            Assert.Equal("domains@registry.asia", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(6, response.Registrant.Address.Count);
            Assert.Equal("Unit 617, Miramar Tower", response.Registrant.Address[0]);
            Assert.Equal("132 Nathan Road", response.Registrant.Address[1]);
            Assert.Equal("Tsim Sha Tsui", response.Registrant.Address[2]);
            Assert.Equal("Kowloon", response.Registrant.Address[3]);
            Assert.Equal("HK", response.Registrant.Address[4]);
            Assert.Equal("HK", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.Equal("FR-11582fd1b4a9", response.AdminContact.RegistryId);
            Assert.Equal(":DotAsia Organisation", response.AdminContact.Name);
            Assert.Equal("DotAsia Organisation", response.AdminContact.Organization);
            Assert.Equal("+852.35202635", response.AdminContact.TelephoneNumber);
            Assert.Equal("domains@registry.asia", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("Unit 617, Miramar Tower", response.AdminContact.Address[0]);
            Assert.Equal("132 Nathan Road", response.AdminContact.Address[1]);
            Assert.Equal("Tsim Sha Tsui", response.AdminContact.Address[2]);
            Assert.Equal("HK", response.AdminContact.Address[3]);
            Assert.Equal("HK", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("FR-11582fd1b4a9", response.BillingContact.RegistryId);
            Assert.Equal("DotAsia Organisation", response.BillingContact.Name);
            Assert.Equal("DotAsia Organisation", response.BillingContact.Organization);
            Assert.Equal("+852.35202635", response.BillingContact.TelephoneNumber);
            Assert.Equal("domains@registry.asia", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(6, response.BillingContact.Address.Count);
            Assert.Equal("Unit 617, Miramar Tower", response.BillingContact.Address[0]);
            Assert.Equal("132 Nathan Road", response.BillingContact.Address[1]);
            Assert.Equal("Tsim Sha Tsui", response.BillingContact.Address[2]);
            Assert.Equal("Kowloon", response.BillingContact.Address[3]);
            Assert.Equal("HK", response.BillingContact.Address[4]);
            Assert.Equal("HK", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.Equal("FR-11582fd1b4a9", response.TechnicalContact.RegistryId);
            Assert.Equal("DotAsia Organisation", response.TechnicalContact.Name);
            Assert.Equal("DotAsia Organisation", response.TechnicalContact.Organization);
            Assert.Equal("+852.35202635", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("domains@registry.asia", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(6, response.TechnicalContact.Address.Count);
            Assert.Equal("Unit 617, Miramar Tower", response.TechnicalContact.Address[0]);
            Assert.Equal("132 Nathan Road", response.TechnicalContact.Address[1]);
            Assert.Equal("Tsim Sha Tsui", response.TechnicalContact.Address[2]);
            Assert.Equal("Kowloon", response.TechnicalContact.Address[3]);
            Assert.Equal("HK", response.TechnicalContact.Address[4]);
            Assert.Equal("HK", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.Equal(2, response.NameServers.Count);
            Assert.Equal("ns1.dotasia.org", response.NameServers[0]);
            Assert.Equal("ns2.dotasia.org", response.NameServers[1]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("OK", response.DomainStatus[0]);

            Assert.Equal(53, response.FieldsParsed);
        }

        [Fact]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "not-found", "not_found.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.NotFound, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("generic/tld/not-found/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }

        [Fact]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "found", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.asia/asia/found/01", response.TemplateName);

            Assert.Equal("cj7.asia", response.DomainName.ToString());
            Assert.Equal("D93126-ASIA", response.RegistryDomainId);

            // Registrar Details
            Assert.Equal("dotASIA R4-ASIA (800046)", response.Registrar.Name);

            Assert.Equal(new DateTime(2014, 01, 15, 22, 20, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.Equal(new DateTime(2008, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Registered);
            Assert.Equal(new DateTime(2015, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.Equal("FR-132aa75b4bf65", response.Registrant.RegistryId);
            Assert.Equal("RAXCO ASSETS CORP.", response.Registrant.Name);
            Assert.Equal("RAXCO ASSETS CORP.", response.Registrant.Organization);
            Assert.Equal("+852.21190333", response.Registrant.TelephoneNumber);
            Assert.Equal("+852.23045326", response.Registrant.FaxNumber);
            Assert.Equal("eddie.yeung@bingogroup.com.hk", response.Registrant.Email);

             // Registrant Address
            Assert.Equal(5, response.Registrant.Address.Count);
            Assert.Equal("RM 1201-1204 12/F", response.Registrant.Address[0]);
            Assert.Equal("SEA BIRD HSE", response.Registrant.Address[1]);
            Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.Registrant.Address[2]);
            Assert.Equal("Hong Kong", response.Registrant.Address[3]);
            Assert.Equal("HK", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.Equal("FR-132aa7afe0967", response.AdminContact.RegistryId);
            Assert.Equal(":Eddie Yeung", response.AdminContact.Name);
            Assert.Equal("RAXCO ASSETS CORP.", response.AdminContact.Organization);
            Assert.Equal("+852.21190333", response.AdminContact.TelephoneNumber);
            Assert.Equal("eddie.yeung@bingogroup.com.hk", response.AdminContact.Email);

             // AdminContact Address
            Assert.Equal(5, response.AdminContact.Address.Count);
            Assert.Equal("RM 1201-1204 12/F", response.AdminContact.Address[0]);
            Assert.Equal("SEA BIRD HSE", response.AdminContact.Address[1]);
            Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.AdminContact.Address[2]);
            Assert.Equal("Hong Kong", response.AdminContact.Address[3]);
            Assert.Equal("HK", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.Equal("FR-132aa774c1b66", response.BillingContact.RegistryId);
            Assert.Equal("Frankie Chan", response.BillingContact.Name);
            Assert.Equal("RAXCO ASSETS CORP.", response.BillingContact.Organization);
            Assert.Equal("+852.21190333", response.BillingContact.TelephoneNumber);
            Assert.Equal("eddie.yeung@bingogroup.com.hk", response.BillingContact.Email);

             // BillingContact Address
            Assert.Equal(5, response.BillingContact.Address.Count);
            Assert.Equal("RM 1201-1204 12/F", response.BillingContact.Address[0]);
            Assert.Equal("SEA BIRD HSE", response.BillingContact.Address[1]);
            Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.BillingContact.Address[2]);
            Assert.Equal("Hong Kong", response.BillingContact.Address[3]);
            Assert.Equal("HK", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.Equal("FR-132aa7afe0967", response.TechnicalContact.RegistryId);
            Assert.Equal("Eddie Yeung", response.TechnicalContact.Name);
            Assert.Equal("RAXCO ASSETS CORP.", response.TechnicalContact.Organization);
            Assert.Equal("+852.21190333", response.TechnicalContact.TelephoneNumber);
            Assert.Equal("eddie.yeung@bingogroup.com.hk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.Equal(5, response.TechnicalContact.Address.Count);
            Assert.Equal("RM 1201-1204 12/F", response.TechnicalContact.Address[0]);
            Assert.Equal("SEA BIRD HSE", response.TechnicalContact.Address[1]);
            Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.TechnicalContact.Address[2]);
            Assert.Equal("Hong Kong", response.TechnicalContact.Address[3]);
            Assert.Equal("HK", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.Equal(6, response.NameServers.Count);
            Assert.Equal("ns1.dnspod.net", response.NameServers[0]);
            Assert.Equal("ns2.dnspod.net", response.NameServers[1]);
            Assert.Equal("ns3.dnspod.net", response.NameServers[2]);
            Assert.Equal("ns4.dnspod.net", response.NameServers[3]);
            Assert.Equal("ns5.dnspod.net", response.NameServers[4]);
            Assert.Equal("ns6.dnspod.net", response.NameServers[5]);

            // Domain Status
            Assert.Equal(1, response.DomainStatus.Count);
            Assert.Equal("OK", response.DomainStatus[0]);

            Assert.Equal(55, response.FieldsParsed);
        }

        [Fact]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "reserved", "reserved.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Reserved, response.Status);

            Assert.Equal(0, response.ParsingErrors);
            Assert.Equal("whois.nic.asia/asia/reserved/01", response.TemplateName);

            Assert.Equal(1, response.FieldsParsed);
        }
    }
}
