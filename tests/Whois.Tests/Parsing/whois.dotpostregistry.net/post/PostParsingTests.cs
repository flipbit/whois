using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dotpostregistry.Net.Post
{
    [TestFixture]
    public class PostParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dotpostregistry.net", "post", "not_found.txt");
            var response = parser.Parse("whois.dotpostregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.dotpostregistry.net", "post", "found.txt");
            var response = parser.Parse("whois.dotpostregistry.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("posteitaliane.post", response.DomainName.ToString());
            Assert.AreEqual("D19482-POST", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Universal Postal Union (R4947-POST)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 09, 21, 12, 07, 40, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 09, 21, 12, 03, 07, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 09, 21, 12, 03, 07, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("ITPI30001", response.Registrant.RegistryId);
            Assert.AreEqual("Poste Italiane", response.Registrant.Name);
            Assert.AreEqual("Poste Italiane", response.Registrant.Organization);
            Assert.AreEqual("+39.0659581", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+39.065942298", response.Registrant.FaxNumber);
            Assert.AreEqual("info@poste.it", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Viale Europa 190", response.Registrant.Address[0]);
            Assert.AreEqual("Rome", response.Registrant.Address[1]);
            Assert.AreEqual("00144", response.Registrant.Address[2]);
            Assert.AreEqual("IT", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("UPU_C1002", response.AdminContact.RegistryId);
            Assert.AreEqual("Giovanni Brardinoni", response.AdminContact.Name);
            Assert.AreEqual("Poste Italiane", response.AdminContact.Organization);
            Assert.AreEqual("+39.0659583671", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+39.0698688651", response.AdminContact.FaxNumber);
            Assert.AreEqual("Giovanni.Brardinoni@Postecom.it", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Viale Europa 175", response.AdminContact.Address[0]);
            Assert.AreEqual("Rome", response.AdminContact.Address[1]);
            Assert.AreEqual("00144", response.AdminContact.Address[2]);
            Assert.AreEqual("IT", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("UPU_C1003", response.BillingContact.RegistryId);
            Assert.AreEqual("Plautina Loreti", response.BillingContact.Name);
            Assert.AreEqual("Poste Italiane", response.BillingContact.Organization);
            Assert.AreEqual("+39.0659585699", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+39.0659589591", response.BillingContact.FaxNumber);
            Assert.AreEqual("loretip@posteitaliane.it", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Viale Europa 175", response.BillingContact.Address[0]);
            Assert.AreEqual("Rome", response.BillingContact.Address[1]);
            Assert.AreEqual("00144", response.BillingContact.Address[2]);
            Assert.AreEqual("IT", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("UPU_C1001", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Andrea Speranza", response.TechnicalContact.Name);
            Assert.AreEqual("Poste Italiane", response.TechnicalContact.Organization);
            Assert.AreEqual("+39.0659583086", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+39.0659582032", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("netsecurity@postecom.it", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Viale Europa 175", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Rome", response.TechnicalContact.Address[1]);
            Assert.AreEqual("00144", response.TechnicalContact.Address[2]);
            Assert.AreEqual("IT", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("dns.poste.it", response.NameServers[0]);
            Assert.AreEqual("dns2.poste.it", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("TRANSFER PROHIBITED", response.DomainStatus[0]);

            Assert.AreEqual("Signed", response.DnsSecStatus);
            Assert.AreEqual(51, response.FieldsParsed);
        }
    }
}
