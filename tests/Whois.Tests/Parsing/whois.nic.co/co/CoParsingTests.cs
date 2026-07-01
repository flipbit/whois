using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Co.Co
{
    [TestFixture]
    public class CoParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.co", "co", "not_found.txt");
            var response = parser.Parse("whois.nic.co", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.co/co/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.co", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.co", "co", "found.txt");
            var response = parser.Parse("whois.nic.co", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.co/co/Found", response.TemplateName);

            Assert.AreEqual("t.co", response.DomainName.ToString());
            Assert.AreEqual("D740225-CO", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("CSC CORPORATE DOMAINS", response.Registrar.Name);
            Assert.AreEqual("299", response.Registrar.IanaId);
            Assert.AreEqual("whois.corporatedomains.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 10, 14, 13, 03, 24, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 04, 26, 07, 50, 40, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 04, 25, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("365684910586C791", response.Registrant.RegistryId);
            Assert.AreEqual("Twitter, Inc.", response.Registrant.Name);
            Assert.AreEqual("Twitter, Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.4152229670", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.4152220922", response.Registrant.FaxNumber);
            Assert.AreEqual("domains@twitter.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(7, response.Registrant.Address.Count);
            Assert.AreEqual("1355 Market Street", response.Registrant.Address[0]);
            Assert.AreEqual("Suite 900", response.Registrant.Address[1]);
            Assert.AreEqual("San Francisco", response.Registrant.Address[2]);
            Assert.AreEqual("CA", response.Registrant.Address[3]);
            Assert.AreEqual("94103", response.Registrant.Address[4]);
            Assert.AreEqual("United States", response.Registrant.Address[5]);
            Assert.AreEqual("US", response.Registrant.Address[6]);


             // AdminContact Details
            Assert.AreEqual("868543810568A633", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Admin", response.AdminContact.Name);
            Assert.AreEqual("Twitter, Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.4152229670", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.4152220922", response.AdminContact.FaxNumber);
            Assert.AreEqual("domains@twitter.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(7, response.AdminContact.Address.Count);
            Assert.AreEqual("1355 Market Street", response.AdminContact.Address[0]);
            Assert.AreEqual("Suite 900", response.AdminContact.Address[1]);
            Assert.AreEqual("San Francisco", response.AdminContact.Address[2]);
            Assert.AreEqual("California", response.AdminContact.Address[3]);
            Assert.AreEqual("94103", response.AdminContact.Address[4]);
            Assert.AreEqual("United States", response.AdminContact.Address[5]);
            Assert.AreEqual("US", response.AdminContact.Address[6]);


             // BillingContact Details
            Assert.AreEqual("341112710590A136", response.BillingContact.RegistryId);
            Assert.AreEqual("ccTLD Billing", response.BillingContact.Name);
            Assert.AreEqual("CSC Corporate Domains, Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.3026365400", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.3026365454", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccTLD-billing@cscinfo.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(6, response.BillingContact.Address.Count);
            Assert.AreEqual("2711 Centerville Rd.", response.BillingContact.Address[0]);
            Assert.AreEqual("Wilmington", response.BillingContact.Address[1]);
            Assert.AreEqual("DE", response.BillingContact.Address[2]);
            Assert.AreEqual("19808", response.BillingContact.Address[3]);
            Assert.AreEqual("United States", response.BillingContact.Address[4]);
            Assert.AreEqual("US", response.BillingContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("42101611057C7478", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Tech Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Twitter, Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.4152229670", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.4152220922", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("domains-tech@twitter.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(7, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1355 Market Street", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Suite 900", response.TechnicalContact.Address[1]);
            Assert.AreEqual("San Francisco", response.TechnicalContact.Address[2]);
            Assert.AreEqual("California", response.TechnicalContact.Address[3]);
            Assert.AreEqual("94103", response.TechnicalContact.Address[4]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[5]);
            Assert.AreEqual("US", response.TechnicalContact.Address[6]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.p34.dynect.net", response.NameServers[0]);
            Assert.AreEqual("ns2.p34.dynect.net", response.NameServers[1]);
            Assert.AreEqual("ns3.p34.dynect.net", response.NameServers[2]);
            Assert.AreEqual("ns4.p34.dynect.net", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);

            Assert.AreEqual(66, response.FieldsParsed);
        }
    }
}
