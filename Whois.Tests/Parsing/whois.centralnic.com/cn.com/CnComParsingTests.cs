using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.CnCom
{
    [TestFixture]
    public class CnComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "cn.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "cn.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("gsn.cn.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO323367", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("united-domains AG", response.Registrar.Name);
            Assert.AreEqual("http://www.united-domains.de", response.Registrar.Url);
            Assert.AreEqual("+498151368670", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 11, 26, 12, 16, 45, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2005, 11, 23, 15, 44, 3, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 11, 23, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1062079", response.Registrant.RegistryId);
            Assert.AreEqual("GSN Electronics Incorporation Pte Ltd", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Straits Trading Building 9 Battery Road 16-08", response.Registrant.Address[0]);
            Assert.AreEqual("Singapore", response.Registrant.Address[1]);
            Assert.AreEqual("049910", response.Registrant.Address[2]);
            Assert.AreEqual("SG", response.Registrant.Address[3]);

            Assert.AreEqual("+65.62336919", response.Registrant.TelephoneNumber);
            Assert.AreEqual("abuse@gsn.in", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("AUTO-DRZK-SNVHSY", response.AdminContact.RegistryId);
            Assert.AreEqual("Pauline Ang", response.AdminContact.Name);
            Assert.AreEqual("GSN Electronics Incorporation Pte Ltd", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Straits Trading Building 9 Battery Road 16-08", response.AdminContact.Address[0]);
            Assert.AreEqual("Singapore", response.AdminContact.Address[1]);
            Assert.AreEqual("049910", response.AdminContact.Address[2]);
            Assert.AreEqual("SG", response.AdminContact.Address[3]);

            Assert.AreEqual("+65.62336919", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("abuse@gsn.in", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("C-UHM65D7-TJGULR", response.BillingContact.RegistryId);
            Assert.AreEqual("Host Master", response.BillingContact.Name);
            Assert.AreEqual("united-domains AG", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Gautinger Str. 10", response.BillingContact.Address[0]);
            Assert.AreEqual("Starnberg", response.BillingContact.Address[1]);
            Assert.AreEqual("Bayern", response.BillingContact.Address[2]);
            Assert.AreEqual("82319", response.BillingContact.Address[3]);
            Assert.AreEqual("DE", response.BillingContact.Address[4]);

            Assert.AreEqual("+49.8151368670", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+49.81513686777", response.BillingContact.FaxNumber);
            Assert.AreEqual("hostmaster@united-domains.de", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("C-UHM65D7-TJGULR", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Host Master", response.TechnicalContact.Name);
            Assert.AreEqual("united-domains AG", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Gautinger Str. 10", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Starnberg", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Bayern", response.TechnicalContact.Address[2]);
            Assert.AreEqual("82319", response.TechnicalContact.Address[3]);
            Assert.AreEqual("DE", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+49.8151368670", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("hostmaster@united-domains.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.meteos.it", response.NameServers[0]);
            Assert.AreEqual("ns2.meteos.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(53, response.FieldsParsed);
        }
    }
}
