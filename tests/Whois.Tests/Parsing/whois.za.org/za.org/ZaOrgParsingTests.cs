using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Za.Org.ZaOrg
{
    [TestFixture]
    public class ZaOrgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.za.org", "za.org", "not_found.txt");
            var response = parser.Parse("whois.za.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.za.org/za.org/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.za.org", response.DomainName.ToString());
            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.za.org", "za.org", "found.txt");
            var response = parser.Parse("whois.za.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.za.org/za.org/Found", response.TemplateName);

            Assert.AreEqual("csa.za.org", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2009, 11, 22, 16, 01, 16, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("W&C Information Consultants CC", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("No 4 Botano Bldg", response.Registrant.Address[0]);
            Assert.AreEqual("Centurion", response.Registrant.Address[1]);
            Assert.AreEqual("0046", response.Registrant.Address[2]);
            Assert.AreEqual("South Africa", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("Willo van der Merwe", response.AdminContact.Name);
            Assert.AreEqual("+27 12 643 0288", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+27 12 643 0287", response.AdminContact.FaxNumber);
            Assert.AreEqual("hostmaster@wcic.co.za", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("W&C Information Consultants CC", response.AdminContact.Address[0]);
            Assert.AreEqual("No 4 Botano Bldg", response.AdminContact.Address[1]);
            Assert.AreEqual("Centurion", response.AdminContact.Address[2]);
            Assert.AreEqual("Gauteng", response.AdminContact.Address[3]);
            Assert.AreEqual("0046", response.AdminContact.Address[4]);
            Assert.AreEqual("South Africa", response.AdminContact.Address[5]);


             // TechnicalContact Details
            Assert.AreEqual("Willo van der Merwe", response.TechnicalContact.Name);
            Assert.AreEqual("+27 12 643 0288", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+27 12 643 0287", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostmaster@wcic.co.za", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("W&C Information Consultants CC", response.TechnicalContact.Address[0]);
            Assert.AreEqual("No 4 Botano Bldg", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Centurion", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Gauteng", response.TechnicalContact.Address[3]);
            Assert.AreEqual("0046", response.TechnicalContact.Address[4]);
            Assert.AreEqual("South Africa", response.TechnicalContact.Address[5]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("blade.wcic.co.za", response.NameServers[0]);
            Assert.AreEqual("sabertooth.wcic.co.za", response.NameServers[1]);
            Assert.AreEqual("ns2.iafrica.com", response.NameServers[2]);

            Assert.AreEqual(31, response.FieldsParsed);
        }
    }
}
