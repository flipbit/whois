using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.KrCom
{
    [TestFixture]
    public class KrComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "kr.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "kr.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("academyart.kr.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO569707", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Network Solutions LLC", response.Registrar.Name);
            Assert.AreEqual("http://www.networksolutions.com/", response.Registrar.Url);
            Assert.AreEqual("+1.9046806600", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 1, 16, 16, 25, 41, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2008, 6, 11, 21, 25, 43, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 6, 11, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("41619876", response.Registrant.RegistryId);
            Assert.AreEqual("Academy of  Art College", response.Registrant.Name);
            Assert.AreEqual("Academy of  Art College", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("79 NEW MONTGOMERY ST", response.Registrant.Address[0]);
            Assert.AreEqual("SAN FRANCISCO", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94105", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);

            Assert.AreEqual("+1.415618350", response.Registrant.TelephoneNumber);
            Assert.AreEqual("clefferts@academyart.edu", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("41619876", response.AdminContact.RegistryId);
            Assert.AreEqual("Academy of  Art College", response.AdminContact.Name);
            Assert.AreEqual("Academy of  Art College", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("79 NEW MONTGOMERY ST", response.AdminContact.Address[0]);
            Assert.AreEqual("SAN FRANCISCO", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94105", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);

            Assert.AreEqual("+1.415618350", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("clefferts@academyart.edu", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("41619877", response.BillingContact.RegistryId);
            Assert.AreEqual("Academy of Art University", response.BillingContact.Name);
            Assert.AreEqual("Academy of Art", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("79 New Montgomery, 3rd Floor", response.BillingContact.Address[0]);
            Assert.AreEqual("SAN FRANCISCO", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("94105", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);

            Assert.AreEqual("+1.4156188582", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.4156186279", response.BillingContact.FaxNumber);
            Assert.AreEqual("Padsuar@academyart.edu", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("41619876", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Academy of  Art College", response.TechnicalContact.Name);
            Assert.AreEqual("Academy of  Art College", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("79 NEW MONTGOMERY ST", response.TechnicalContact.Address[0]);
            Assert.AreEqual("SAN FRANCISCO", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94105", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+1.415618350", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("clefferts@academyart.edu", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(5, response.NameServers.Count);
            Assert.AreEqual("ns1.academyart.edu", response.NameServers[0]);
            Assert.AreEqual("dbru.br.ns.els-gms.att.net", response.NameServers[1]);
            Assert.AreEqual("dmtu.mt.ns.els-gms.att.net", response.NameServers[2]);
            Assert.AreEqual("cbru.br.ns.els-gms.att.net", response.NameServers[3]);
            Assert.AreEqual("cmtu.mt.ns.els-gms.att.net", response.NameServers[4]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(59, response.FieldsParsed);
        }
    }
}
