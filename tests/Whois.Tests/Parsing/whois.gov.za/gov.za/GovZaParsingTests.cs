using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Gov.Za.GovZa
{
    [TestFixture]
    public class GovZaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.gov.za", "gov.za", "not_found.txt");
            var response = parser.Parse("whois.gov.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.gov.za/gov.za/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.gov.za", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.gov.za", "gov.za", "found.txt");
            var response = parser.Parse("whois.gov.za", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.gov.za/gov.za/Found", response.TemplateName);

            Assert.AreEqual("dha.gov.za", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 09, 03, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Department of Home Affairs", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(2, response.Registrant.Address.Count);
            Assert.AreEqual("Private Bag x114,Pretoria,", response.Registrant.Address[0]);
            Assert.AreEqual("0001", response.Registrant.Address[1]);


             // AdminContact Details
            Assert.AreEqual("Zakhele Khuzwayo", response.AdminContact.Name);
            Assert.AreEqual("Department of Home Affairs", response.AdminContact.Organization);
            Assert.AreEqual("zakhele.khuzwayo@dha.gov.za", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(2, response.AdminContact.Address.Count);
            Assert.AreEqual("Private Bag x114,0001,", response.AdminContact.Address[0]);
            Assert.AreEqual("Pretoria", response.AdminContact.Address[1]);


             // TechnicalContact Details
            Assert.AreEqual("David D. Sussens", response.TechnicalContact.Name);
            Assert.AreEqual("SITA", response.TechnicalContact.Organization);
            Assert.AreEqual("david.sussens@sita.co.za", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(2, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Private Bag x114,Pretoria,", response.TechnicalContact.Address[0]);
            Assert.AreEqual("0001", response.TechnicalContact.Address[1]);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("ns1.dha.gov.za", response.NameServers[0]);

            Assert.AreEqual(17, response.FieldsParsed);
        }
    }
}
