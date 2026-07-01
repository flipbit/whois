using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.College.College
{
    [TestFixture]
    public class CollegeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.college", "college", "not_found.txt");
            var response = parser.Parse("whois.nic.college", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.college", "college", "found.txt");
            var response = parser.Parse("whois.nic.college", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.college", response.DomainName.ToString());
            Assert.AreEqual("D1465621-CNIC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("CentralNic Ltd", response.Registrar.Name);
            Assert.AreEqual("9999", response.Registrar.IanaId);
            Assert.AreEqual("http://www.centralnic.com/", response.Registrar.Url);
            Assert.AreEqual("whois.centralnic.com", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2014, 09, 12, 00, 15, 47, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 09, 11, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H5178905", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("XYZ.COM LLC", response.Registrant.Organization);
            Assert.AreEqual("+1.8009998422", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.7023578299", response.Registrant.FaxNumber);
            Assert.AreEqual("icann@xyz.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("2121 E Tropicana Ave Suite #2", response.Registrant.Address[0]);
            Assert.AreEqual("Las Vegas", response.Registrant.Address[1]);
            Assert.AreEqual("NV", response.Registrant.Address[2]);
            Assert.AreEqual("89119", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("H5178905", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("XYZ.COM LLC", response.AdminContact.Organization);
            Assert.AreEqual("+1.8009998422", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.7023578299", response.AdminContact.FaxNumber);
            Assert.AreEqual("icann@xyz.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("2121 E Tropicana Ave Suite #2", response.AdminContact.Address[0]);
            Assert.AreEqual("Las Vegas", response.AdminContact.Address[1]);
            Assert.AreEqual("NV", response.AdminContact.Address[2]);
            Assert.AreEqual("89119", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("H5178905", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("XYZ.COM LLC", response.BillingContact.Organization);
            Assert.AreEqual("+1.8009998422", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.7023578299", response.BillingContact.FaxNumber);
            Assert.AreEqual("icann@xyz.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("2121 E Tropicana Ave Suite #2", response.BillingContact.Address[0]);
            Assert.AreEqual("Las Vegas", response.BillingContact.Address[1]);
            Assert.AreEqual("NV", response.BillingContact.Address[2]);
            Assert.AreEqual("89119", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("H5178905", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.TechnicalContact.Name);
            Assert.AreEqual("XYZ.COM LLC", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.8009998422", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.7023578299", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("icann@xyz.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2121 E Tropicana Ave Suite #2", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Las Vegas", response.TechnicalContact.Address[1]);
            Assert.AreEqual("NV", response.TechnicalContact.Address[2]);
            Assert.AreEqual("89119", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns0.centralnic-dns.com", response.NameServers[0]);
            Assert.AreEqual("ns1.centralnic-dns.com", response.NameServers[1]);
            Assert.AreEqual("ns2.centralnic-dns.com", response.NameServers[2]);
            Assert.AreEqual("ns3.centralnic-dns.com", response.NameServers[3]);
            Assert.AreEqual("ns4.centralnic-dns.com", response.NameServers[4]);
            Assert.AreEqual("ns5.centralnic-dns.com", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[1]);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[2]);
            Assert.AreEqual("serverRenewProhibited", response.DomainStatus[3]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(65, response.FieldsParsed);
        }
    }
}
