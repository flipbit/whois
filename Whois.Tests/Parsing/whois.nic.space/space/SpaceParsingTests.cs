using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Space.Space
{
    [TestFixture]
    public class SpaceParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.space", "space", "not_found.txt");
            var response = parser.Parse("whois.nic.space", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.space", "space", "found.txt");
            var response = parser.Parse("whois.nic.space", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.space", response.DomainName.ToString());
            Assert.AreEqual("D2361836-CNIC", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("CentralNic Ltd", response.Registrar.Name);
            Assert.AreEqual("9999", response.Registrar.IanaId);
            Assert.AreEqual("http://www.centralnic.com/", response.Registrar.Url);
            Assert.AreEqual("whois.centralnic.com", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2015, 04, 04, 00, 14, 21, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2014, 04, 10, 09, 14, 07, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 04, 10, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("C11480", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("CentralNic Ltd", response.Registrant.Organization);
            Assert.AreEqual("+44.2033880600", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+44.2033880601", response.Registrant.FaxNumber);
            Assert.AreEqual("domains@centralnic.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.Registrant.Address[0]);
            Assert.AreEqual("London", response.Registrant.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.Registrant.Address[2]);
            Assert.AreEqual("GB", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("C11480", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("CentralNic Ltd", response.AdminContact.Organization);
            Assert.AreEqual("+44.2033880600", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+44.2033880601", response.AdminContact.FaxNumber);
            Assert.AreEqual("domains@centralnic.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.AdminContact.Address[0]);
            Assert.AreEqual("London", response.AdminContact.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.AdminContact.Address[2]);
            Assert.AreEqual("GB", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("C11480", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("CentralNic Ltd", response.BillingContact.Organization);
            Assert.AreEqual("+44.2033880600", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+44.2033880601", response.BillingContact.FaxNumber);
            Assert.AreEqual("domains@centralnic.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.BillingContact.Address[0]);
            Assert.AreEqual("London", response.BillingContact.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.BillingContact.Address[2]);
            Assert.AreEqual("GB", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("C11480", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.TechnicalContact.Name);
            Assert.AreEqual("CentralNic Ltd", response.TechnicalContact.Organization);
            Assert.AreEqual("+44.2033880600", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+44.2033880601", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("domains@centralnic.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("35-39 Moorgate", response.TechnicalContact.Address[0]);
            Assert.AreEqual("London", response.TechnicalContact.Address[1]);
            Assert.AreEqual("EC2R 6AR", response.TechnicalContact.Address[2]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns0.centralnic-dns.com", response.NameServers[0]);
            Assert.AreEqual("ns1.centralnic-dns.com", response.NameServers[1]);
            Assert.AreEqual("ns2.centralnic-dns.com", response.NameServers[2]);
            Assert.AreEqual("ns3.centralnic-dns.com", response.NameServers[3]);
            Assert.AreEqual("ns4.centralnic-dns.com", response.NameServers[4]);
            Assert.AreEqual("ns5.centralnic-dns.com", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(58, response.FieldsParsed);
        }
    }
}
