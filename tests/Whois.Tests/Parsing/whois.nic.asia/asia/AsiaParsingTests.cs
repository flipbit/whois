using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Asia.Asia
{
    [TestFixture]
    public class AsiaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "found.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.asia/asia/Found", response.TemplateName);

            Assert.AreEqual("novalash.asia", response.DomainName.ToString());
            Assert.AreEqual("D1032500-ASIA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("007Names, Inc. R94-ASIA (91)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 10, 01, 03, 30, 34, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 10, 30, 22, 54, 15, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 10, 30, 22, 54, 15, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("7AERFN4T4P", response.Registrant.RegistryId);
            Assert.AreEqual("Sophy Merszei", response.Registrant.Name);
            Assert.AreEqual("Novalash", response.Registrant.Organization);
            Assert.AreEqual("+1.8664301261", response.Registrant.TelephoneNumber);
            Assert.AreEqual("khickman@awsp.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("3701 W. Alabama", response.Registrant.Address[0]);
            Assert.AreEqual("Houston", response.Registrant.Address[1]);
            Assert.AreEqual("TX", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);
            Assert.AreEqual("77027", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("5MTMZMT3K1", response.AdminContact.RegistryId);
            Assert.AreEqual(":Sophy Merszei", response.AdminContact.Name);
            Assert.AreEqual("Novalash", response.AdminContact.Organization);
            Assert.AreEqual("+1.8664301261", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("khickman@awsp.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("3701 W. Alabama", response.AdminContact.Address[0]);
            Assert.AreEqual("Houston", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);
            Assert.AreEqual("77027", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("5MTMZMT3K1", response.BillingContact.RegistryId);
            Assert.AreEqual("Sophy Merszei", response.BillingContact.Name);
            Assert.AreEqual("Novalash", response.BillingContact.Organization);
            Assert.AreEqual("+1.8664301261", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("khickman@awsp.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("3701 W. Alabama", response.BillingContact.Address[0]);
            Assert.AreEqual("Houston", response.BillingContact.Address[1]);
            Assert.AreEqual("TX", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);
            Assert.AreEqual("77027", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("FR-11594d9eed91", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Edward Lin", response.TechnicalContact.Name);
            Assert.AreEqual("EDM Enterprise Co., LTD", response.TechnicalContact.Organization);
            Assert.AreEqual("+886.425625115", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("doamina@yahoo.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("No. 10 Lane 241, Chung Shan Road", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Shen Kang Hsiang", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Taichung Hsien", response.TechnicalContact.Address[2]);
            Assert.AreEqual("TW", response.TechnicalContact.Address[3]);
            Assert.AreEqual("35000", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.rackspace.com", response.NameServers[0]);
            Assert.AreEqual("ns.raskspace.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("CLIENT DELETE PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("CLIENT TRANSFER PROHIBITED", response.DomainStatus[1]);

            Assert.AreEqual(50, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "other_status_single.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.asia/asia/Found", response.TemplateName);

            Assert.AreEqual("cj7.asia", response.DomainName.ToString());
            Assert.AreEqual("D93126-ASIA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("dotASIA R4-ASIA (9998)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2008, 03, 16, 04, 30, 25, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("FR-1158300cc88a", response.Registrant.RegistryId);
            Assert.AreEqual("Pioneer Domain (Temporary Delegation)", response.Registrant.Name);
            Assert.AreEqual("DotAsia Organisation", response.Registrant.Organization);
            Assert.AreEqual("+852.35202635", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domains@registry.asia", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Unit 617, Miramar Tower", response.Registrant.Address[0]);
            Assert.AreEqual("132 Nathan Road", response.Registrant.Address[1]);
            Assert.AreEqual("Tsim Sha Tsui", response.Registrant.Address[2]);
            Assert.AreEqual("Kowloon", response.Registrant.Address[3]);
            Assert.AreEqual("HK", response.Registrant.Address[4]);
            Assert.AreEqual("HK", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("FR-11582fd1b4a9", response.AdminContact.RegistryId);
            Assert.AreEqual(":DotAsia Organisation", response.AdminContact.Name);
            Assert.AreEqual("DotAsia Organisation", response.AdminContact.Organization);
            Assert.AreEqual("+852.35202635", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domains@registry.asia", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Unit 617, Miramar Tower", response.AdminContact.Address[0]);
            Assert.AreEqual("132 Nathan Road", response.AdminContact.Address[1]);
            Assert.AreEqual("Tsim Sha Tsui", response.AdminContact.Address[2]);
            Assert.AreEqual("HK", response.AdminContact.Address[3]);
            Assert.AreEqual("HK", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("FR-11582fd1b4a9", response.BillingContact.RegistryId);
            Assert.AreEqual("DotAsia Organisation", response.BillingContact.Name);
            Assert.AreEqual("DotAsia Organisation", response.BillingContact.Organization);
            Assert.AreEqual("+852.35202635", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("domains@registry.asia", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("Unit 617, Miramar Tower", response.BillingContact.Address[0]);
            Assert.AreEqual("132 Nathan Road", response.BillingContact.Address[1]);
            Assert.AreEqual("Tsim Sha Tsui", response.BillingContact.Address[2]);
            Assert.AreEqual("Kowloon", response.BillingContact.Address[3]);
            Assert.AreEqual("HK", response.BillingContact.Address[4]);
            Assert.AreEqual("HK", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("FR-11582fd1b4a9", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DotAsia Organisation", response.TechnicalContact.Name);
            Assert.AreEqual("DotAsia Organisation", response.TechnicalContact.Organization);
            Assert.AreEqual("+852.35202635", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domains@registry.asia", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Unit 617, Miramar Tower", response.TechnicalContact.Address[0]);
            Assert.AreEqual("132 Nathan Road", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Tsim Sha Tsui", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Kowloon", response.TechnicalContact.Address[3]);
            Assert.AreEqual("HK", response.TechnicalContact.Address[4]);
            Assert.AreEqual("HK", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.dotasia.org", response.NameServers[0]);
            Assert.AreEqual("ns2.dotasia.org", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual(53, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "not_found.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.asia/asia/Found", response.TemplateName);

            Assert.AreEqual("cj7.asia", response.DomainName.ToString());
            Assert.AreEqual("D93126-ASIA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("dotASIA R4-ASIA (800046)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 01, 15, 22, 20, 16, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("FR-132aa75b4bf65", response.Registrant.RegistryId);
            Assert.AreEqual("RAXCO ASSETS CORP.", response.Registrant.Name);
            Assert.AreEqual("RAXCO ASSETS CORP.", response.Registrant.Organization);
            Assert.AreEqual("+852.21190333", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+852.23045326", response.Registrant.FaxNumber);
            Assert.AreEqual("eddie.yeung@bingogroup.com.hk", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("RM 1201-1204 12/F", response.Registrant.Address[0]);
            Assert.AreEqual("SEA BIRD HSE", response.Registrant.Address[1]);
            Assert.AreEqual("22-28 WYNDHAM ST CENTRAL HK", response.Registrant.Address[2]);
            Assert.AreEqual("Hong Kong", response.Registrant.Address[3]);
            Assert.AreEqual("HK", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("FR-132aa7afe0967", response.AdminContact.RegistryId);
            Assert.AreEqual(":Eddie Yeung", response.AdminContact.Name);
            Assert.AreEqual("RAXCO ASSETS CORP.", response.AdminContact.Organization);
            Assert.AreEqual("+852.21190333", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("eddie.yeung@bingogroup.com.hk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("RM 1201-1204 12/F", response.AdminContact.Address[0]);
            Assert.AreEqual("SEA BIRD HSE", response.AdminContact.Address[1]);
            Assert.AreEqual("22-28 WYNDHAM ST CENTRAL HK", response.AdminContact.Address[2]);
            Assert.AreEqual("Hong Kong", response.AdminContact.Address[3]);
            Assert.AreEqual("HK", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("FR-132aa774c1b66", response.BillingContact.RegistryId);
            Assert.AreEqual("Frankie Chan", response.BillingContact.Name);
            Assert.AreEqual("RAXCO ASSETS CORP.", response.BillingContact.Organization);
            Assert.AreEqual("+852.21190333", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("eddie.yeung@bingogroup.com.hk", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("RM 1201-1204 12/F", response.BillingContact.Address[0]);
            Assert.AreEqual("SEA BIRD HSE", response.BillingContact.Address[1]);
            Assert.AreEqual("22-28 WYNDHAM ST CENTRAL HK", response.BillingContact.Address[2]);
            Assert.AreEqual("Hong Kong", response.BillingContact.Address[3]);
            Assert.AreEqual("HK", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("FR-132aa7afe0967", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Eddie Yeung", response.TechnicalContact.Name);
            Assert.AreEqual("RAXCO ASSETS CORP.", response.TechnicalContact.Organization);
            Assert.AreEqual("+852.21190333", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("eddie.yeung@bingogroup.com.hk", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("RM 1201-1204 12/F", response.TechnicalContact.Address[0]);
            Assert.AreEqual("SEA BIRD HSE", response.TechnicalContact.Address[1]);
            Assert.AreEqual("22-28 WYNDHAM ST CENTRAL HK", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Hong Kong", response.TechnicalContact.Address[3]);
            Assert.AreEqual("HK", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns1.dnspod.net", response.NameServers[0]);
            Assert.AreEqual("ns2.dnspod.net", response.NameServers[1]);
            Assert.AreEqual("ns3.dnspod.net", response.NameServers[2]);
            Assert.AreEqual("ns4.dnspod.net", response.NameServers[3]);
            Assert.AreEqual("ns5.dnspod.net", response.NameServers[4]);
            Assert.AreEqual("ns6.dnspod.net", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual(55, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.asia", "asia", "reserved.txt");
            var response = parser.Parse("whois.nic.asia", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.asia/asia/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }
    }
}
