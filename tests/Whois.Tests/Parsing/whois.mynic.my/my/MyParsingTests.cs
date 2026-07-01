using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Mynic.My.My
{
    [TestFixture]
    public class MyParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.mynic.my", "my", "not_found.txt");
            var response = parser.Parse("whois.mynic.my", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.mynic.my/my/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.my", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.mynic.my", "my", "found.txt");
            var response = parser.Parse("whois.mynic.my", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.mynic.my/my/Found", response.TemplateName);

            Assert.AreEqual("google.my", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 10, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 05, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 05, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("INTEG4.ORG", response.Registrant.RegistryId);
            Assert.AreEqual("Integricity Corporation Sdn. Bhd.", response.Registrant.Name);
            Assert.AreEqual("(532745-U)", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("L1-46, First Floor, SStwo Mall", response.Registrant.Address[0]);
            Assert.AreEqual("40, Jalan SS2/72", response.Registrant.Address[1]);
            Assert.AreEqual("47300 Petaling Jaya", response.Registrant.Address[2]);
            Assert.AreEqual("Selangor", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("ALEXLAM3.CON", response.AdminContact.RegistryId);
            Assert.AreEqual("Network Admin Team", response.AdminContact.Name);
            Assert.AreEqual("Integricity Corporation Sdn. Bhd.", response.AdminContact.Organization);
            Assert.AreEqual("603-79570700", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("603-79572700", response.AdminContact.FaxNumber);
            Assert.AreEqual("domain@fatservers.my", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("L1-46, First Floor, SStwo Mall", response.AdminContact.Address[0]);
            Assert.AreEqual("40, Jalan SS2/72", response.AdminContact.Address[1]);
            Assert.AreEqual("47300 Petaling Jaya", response.AdminContact.Address[2]);
            Assert.AreEqual("Selangor", response.AdminContact.Address[3]);
            Assert.AreEqual("Malaysia", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("ALEXLAM3.CON", response.BillingContact.RegistryId);
            Assert.AreEqual("Network Admin Team", response.BillingContact.Name);
            Assert.AreEqual("Integricity Corporation Sdn. Bhd.", response.BillingContact.Organization);
            Assert.AreEqual("603-79570700", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("603-79572700", response.BillingContact.FaxNumber);
            Assert.AreEqual("domain@fatservers.my", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("L1-46, First Floor, SStwo Mall", response.BillingContact.Address[0]);
            Assert.AreEqual("40, Jalan SS2/72", response.BillingContact.Address[1]);
            Assert.AreEqual("47300 Petaling Jaya", response.BillingContact.Address[2]);
            Assert.AreEqual("Selangor", response.BillingContact.Address[3]);
            Assert.AreEqual("Malaysia", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("ALEXLAM3.CON", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Network Admin Team", response.TechnicalContact.Name);
            Assert.AreEqual("Integricity Corporation Sdn. Bhd.", response.TechnicalContact.Organization);
            Assert.AreEqual("603-79570700", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("603-79572700", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("domain@fatservers.my", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("L1-46, First Floor, SStwo Mall", response.TechnicalContact.Address[0]);
            Assert.AreEqual("40, Jalan SS2/72", response.TechnicalContact.Address[1]);
            Assert.AreEqual("47300 Petaling Jaya", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Selangor", response.TechnicalContact.Address[3]);
            Assert.AreEqual("Malaysia", response.TechnicalContact.Address[4]);


            Assert.AreEqual(45, response.FieldsParsed);
        }
    }
}
