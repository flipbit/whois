using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.GbNet
{
    [TestFixture]
    public class GbNetParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "gb.net", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "gb.net", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("hotel.gb.net", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO1423750", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Gandi SAS", response.Registrar.Name);
            Assert.AreEqual("http://www.gandi.net/", response.Registrar.Url);
            Assert.AreEqual("+33 1 7039 3740", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 8, 30, 12, 42, 9, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2013, 8, 25, 12, 36, 24, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 8, 25, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("R1149-GANDI-PRYP", response.Registrant.RegistryId);
            Assert.AreEqual("Heinz Pierre Roeser", response.Registrant.Name);
            Assert.AreEqual("Roevertrieb", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Friedensstr. 77", response.Registrant.Address[0]);
            Assert.AreEqual("Grevenbroich", response.Registrant.Address[1]);
            Assert.AreEqual("41517", response.Registrant.Address[2]);
            Assert.AreEqual("DE", response.Registrant.Address[3]);

            Assert.AreEqual("+49.218145077", response.Registrant.TelephoneNumber);
            Assert.AreEqual("roevertrieb@aol.com", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("R1149-GANDI-PRYP", response.AdminContact.RegistryId);
            Assert.AreEqual("Heinz Pierre Roeser", response.AdminContact.Name);
            Assert.AreEqual("Roevertrieb", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Friedensstr. 77", response.AdminContact.Address[0]);
            Assert.AreEqual("Grevenbroich", response.AdminContact.Address[1]);
            Assert.AreEqual("41517", response.AdminContact.Address[2]);
            Assert.AreEqual("DE", response.AdminContact.Address[3]);

            Assert.AreEqual("+49.218145077", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("roevertrieb@aol.com", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("R1149-GANDI-PRYP", response.BillingContact.RegistryId);
            Assert.AreEqual("Heinz Pierre Roeser", response.BillingContact.Name);
            Assert.AreEqual("Roevertrieb", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Friedensstr. 77", response.BillingContact.Address[0]);
            Assert.AreEqual("Grevenbroich", response.BillingContact.Address[1]);
            Assert.AreEqual("41517", response.BillingContact.Address[2]);
            Assert.AreEqual("DE", response.BillingContact.Address[3]);

            Assert.AreEqual("+49.218145077", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("roevertrieb@aol.com", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("R1149-GANDI-PRYP", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Heinz Pierre Roeser", response.TechnicalContact.Name);
            Assert.AreEqual("Roevertrieb", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Friedensstr. 77", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Grevenbroich", response.TechnicalContact.Address[1]);
            Assert.AreEqual("41517", response.TechnicalContact.Address[2]);
            Assert.AreEqual("DE", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+49.218145077", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("roevertrieb@aol.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("b.dns.gandi.net", response.NameServers[0]);
            Assert.AreEqual("c.dns.gandi.net", response.NameServers[1]);
            Assert.AreEqual("a.dns.gandi.net", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(52, response.FieldsParsed);
        }
    }
}
