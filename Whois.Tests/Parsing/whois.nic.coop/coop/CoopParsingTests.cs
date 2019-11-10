using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Coop.Coop
{
    [TestFixture]
    public class CoopParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.coop/coop/Found", response.TemplateName);

            Assert.AreEqual("moscowfood.coop", response.DomainName.ToString());
            Assert.AreEqual("5662D-COOP", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Domain Bank Inc.", response.Registrar.Name);
            Assert.AreEqual("31", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2001, 10, 09, 04, 36, 36, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 01, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("71764C-COOP", response.Registrant.RegistryId);
            Assert.AreEqual("Kenna Eaton", response.Registrant.Name);
            Assert.AreEqual("Moscow Food Co-op", response.Registrant.Organization);
            Assert.AreEqual("+1.2088828537", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.2088828082", response.Registrant.FaxNumber);
            Assert.AreEqual("kenna@moscowfood.coop", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("P. O. Box 9485", response.Registrant.Address[0]);
            Assert.AreEqual("Moscow", response.Registrant.Address[1]);
            Assert.AreEqual("ID", response.Registrant.Address[2]);
            Assert.AreEqual("83843", response.Registrant.Address[3]);
            Assert.AreEqual("United States", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("74326C-COOP", response.AdminContact.RegistryId);
            Assert.AreEqual("Carol Spurling", response.AdminContact.Name);
            Assert.AreEqual("Moscow Food Co-op", response.AdminContact.Organization);
            Assert.AreEqual("+1.2086690763", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("outreach@moscowfood.coop", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("P. O. Box 9485", response.AdminContact.Address[0]);
            Assert.AreEqual("Moscow", response.AdminContact.Address[1]);
            Assert.AreEqual("ID", response.AdminContact.Address[2]);
            Assert.AreEqual("83843", response.AdminContact.Address[3]);
            Assert.AreEqual("United States", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("75003C-COOP", response.BillingContact.RegistryId);
            Assert.AreEqual("Sandy Hughes", response.BillingContact.Name);
            Assert.AreEqual("Moscow Food Co-op", response.BillingContact.Organization);
            Assert.AreEqual("+1.2088828537", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2088828082", response.BillingContact.FaxNumber);
            Assert.AreEqual("payable@moscowfood.coop", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("P. O. Box 9485", response.BillingContact.Address[0]);
            Assert.AreEqual("Moscow", response.BillingContact.Address[1]);
            Assert.AreEqual("ID", response.BillingContact.Address[2]);
            Assert.AreEqual("83843", response.BillingContact.Address[3]);
            Assert.AreEqual("United States", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("75916C-COOP", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Joseph Erhard-Hudson", response.TechnicalContact.Name);
            Assert.AreEqual("Moscow Food Co-op", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.2088828537", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.2088828082", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("joseph@moscowfood.coop", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("P. O. Box 9485", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Moscow", response.TechnicalContact.Address[1]);
            Assert.AreEqual("ID", response.TechnicalContact.Address[2]);
            Assert.AreEqual("83843", response.TechnicalContact.Address[3]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.west-datacenter.net", response.NameServers[0]);
            Assert.AreEqual("ns1.west-datacenter.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[2]);

            Assert.AreEqual(59, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "other_status_single.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.coop/coop/Found", response.TemplateName);

            Assert.AreEqual("calgary.coop", response.DomainName.ToString());
            Assert.AreEqual("7441D-COOP", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("domains.coop", response.Registrar.Name);
            Assert.AreEqual("465", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2002, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2012, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("54100C-COOP", response.Registrant.RegistryId);
            Assert.AreEqual("Net Admin", response.Registrant.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.Registrant.Organization);
            Assert.AreEqual("+1.4032196025", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.Registrant.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.Registrant.Address[0]);
            Assert.AreEqual("Calgary", response.Registrant.Address[1]);
            Assert.AreEqual("AB", response.Registrant.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.Registrant.Address[3]);
            Assert.AreEqual("Canada", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("54100C-COOP", response.AdminContact.RegistryId);
            Assert.AreEqual("Net Admin", response.AdminContact.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.AdminContact.Organization);
            Assert.AreEqual("+1.4032196025", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.AdminContact.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.AdminContact.Address[0]);
            Assert.AreEqual("Calgary", response.AdminContact.Address[1]);
            Assert.AreEqual("AB", response.AdminContact.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.AdminContact.Address[3]);
            Assert.AreEqual("Canada", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("54100C-COOP", response.BillingContact.RegistryId);
            Assert.AreEqual("Net Admin", response.BillingContact.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.BillingContact.Organization);
            Assert.AreEqual("+1.4032196025", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.BillingContact.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.BillingContact.Address[0]);
            Assert.AreEqual("Calgary", response.BillingContact.Address[1]);
            Assert.AreEqual("AB", response.BillingContact.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.BillingContact.Address[3]);
            Assert.AreEqual("Canada", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("54100C-COOP", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Net Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.4032196025", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Calgary", response.TechnicalContact.Address[1]);
            Assert.AreEqual("AB", response.TechnicalContact.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Canada", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.calgarycoop.net", response.NameServers[0]);
            Assert.AreEqual("ns2.calgarycoop.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(58, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "not_found.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.coop/coop/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.coop", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.coop", "coop", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.coop", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.coop/coop/Found", response.TemplateName);

            Assert.AreEqual("calgary.coop", response.DomainName.ToString());
            Assert.AreEqual("7441D-COOP", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("domains.coop", response.Registrar.Name);
            Assert.AreEqual("465", response.Registrar.IanaId);

            Assert.AreEqual(new DateTime(2002, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("54100C-COOP", response.Registrant.RegistryId);
            Assert.AreEqual("Net Admin", response.Registrant.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.Registrant.Organization);
            Assert.AreEqual("+1.4032196025", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.Registrant.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.Registrant.Address[0]);
            Assert.AreEqual("Calgary", response.Registrant.Address[1]);
            Assert.AreEqual("AB", response.Registrant.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.Registrant.Address[3]);
            Assert.AreEqual("Canada", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("54100C-COOP", response.AdminContact.RegistryId);
            Assert.AreEqual("Net Admin", response.AdminContact.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.AdminContact.Organization);
            Assert.AreEqual("+1.4032196025", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.AdminContact.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.AdminContact.Address[0]);
            Assert.AreEqual("Calgary", response.AdminContact.Address[1]);
            Assert.AreEqual("AB", response.AdminContact.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.AdminContact.Address[3]);
            Assert.AreEqual("Canada", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("54100C-COOP", response.BillingContact.RegistryId);
            Assert.AreEqual("Net Admin", response.BillingContact.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.BillingContact.Organization);
            Assert.AreEqual("+1.4032196025", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.BillingContact.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.BillingContact.Address[0]);
            Assert.AreEqual("Calgary", response.BillingContact.Address[1]);
            Assert.AreEqual("AB", response.BillingContact.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.BillingContact.Address[3]);
            Assert.AreEqual("Canada", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("54100C-COOP", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Net Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Calgary Co operative Association Limited", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.4032196025", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.4032995416", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("netadmin@calgarycoop.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2735 39 Avenue NE", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Calgary", response.TechnicalContact.Address[1]);
            Assert.AreEqual("AB", response.TechnicalContact.Address[2]);
            Assert.AreEqual("T1Y 7C7", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Canada", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.calgarycoop.net", response.NameServers[0]);
            Assert.AreEqual("ns2.calgarycoop.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual(58, response.FieldsParsed);
        }
    }
}
