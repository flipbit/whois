using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ja.Net.GovUk
{
    [TestFixture]
    public class GovUkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.ja.net", "gov.uk", "not_found.txt");
            var response = parser.Parse("whois.ja.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ja.net/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.gov.uk", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ja.net", "gov.uk", "found.txt");
            var response = parser.Parse("whois.ja.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ja.net/Found", response.TemplateName);

            Assert.AreEqual("direct.gov.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NTT Europe Online Ltd", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 01, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 09, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 03, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Directgov", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("Directgov Director", response.AdminContact.Name);
            Assert.AreEqual("+44 207 261 8723", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+44 207 261 8696", response.AdminContact.FaxNumber);
            Assert.AreEqual("helpdesk@directgov.gsi.gov.uk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Hercules House", response.AdminContact.Address[0]);
            Assert.AreEqual("Hercules Road", response.AdminContact.Address[1]);
            Assert.AreEqual("London", response.AdminContact.Address[2]);
            Assert.AreEqual("SE1 7DU", response.AdminContact.Address[3]);
            Assert.AreEqual("United Kingdom", response.AdminContact.Address[4]);


            // Nameservers
            Assert.AreEqual(8, response.NameServers.Count);
            Assert.AreEqual("eur5.akam.net", response.NameServers[0]);
            Assert.AreEqual("eur6.akam.net", response.NameServers[1]);
            Assert.AreEqual("ns1-173.akam.net", response.NameServers[2]);
            Assert.AreEqual("ns1-31.akam.net", response.NameServers[3]);
            Assert.AreEqual("usc4.akam.net", response.NameServers[4]);
            Assert.AreEqual("use10.akam.net", response.NameServers[5]);
            Assert.AreEqual("usw2.akam.net", response.NameServers[6]);
            Assert.AreEqual("usw4.akam.net", response.NameServers[7]);

            Assert.AreEqual(24, response.FieldsParsed);
        }
    }
}
