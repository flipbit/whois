using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Bo.Bo
{
    [TestFixture]
    public class BoParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.bo", "bo", "not_found.txt");
            var response = parser.Parse("whois.nic.bo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.bo/bo/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.bo", "bo", "found.txt");
            var response = parser.Parse("whois.nic.bo", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.bo/bo/Found", response.TemplateName);

            Assert.AreEqual("google.bo", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2006, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 08, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("16502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("mail@nameaction.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Estados Unidos de America", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("1600 Amphitheatre Parkway Mountain View", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("MarkMonitor Inc.", response.AdminContact.Organization);
            Assert.AreEqual("12083895740", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Estados Unidos de America", response.AdminContact.Address[0]);
            Assert.AreEqual("Boise", response.AdminContact.Address[1]);
            Assert.AreEqual("391 N. Ancestor pl.", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.AreEqual("12083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("Estados Unidos de America", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("391 N. Ancestor pl.", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Name);
            Assert.AreEqual("MarkMonitor", response.TechnicalContact.Organization);
            Assert.AreEqual("+1208389 5783", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("mail@nameaction.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("USA", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise, Idaho  83704", response.TechnicalContact.Address[1]);
            Assert.AreEqual("391 N. Ancestor Place", response.TechnicalContact.Address[2]);


            Assert.AreEqual(32, response.FieldsParsed);
        }
    }
}
