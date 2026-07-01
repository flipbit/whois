using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kg.Kg
{
    [TestFixture]
    public class KgParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.kg", "kg", "not_found.txt");
            var response = parser.Parse("whois.kg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kg/kg/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.kg", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.kg", "kg", "found.txt");
            var response = parser.Parse("whois.kg", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kg/kg/Found", response.TemplateName);

            Assert.AreEqual("google.kg", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 04, 19, 21, 47, 14, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 02, 10, 09, 42, 42, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 03, 30, 23, 59, 00, 000, DateTimeKind.Utc), response.Expiration);

             // AdminContact Details
            Assert.AreEqual("8386-KG", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.AdminContact.Name);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);


             // BillingContact Details
            Assert.AreEqual("5935-KG", response.BillingContact.RegistryId);
            Assert.AreEqual("Markmonitor", response.BillingContact.Name);
            Assert.AreEqual("+12083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+12083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(1, response.BillingContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place Boise, ID 83704", response.BillingContact.Address[0]);


             // TechnicalContact Details
            Assert.AreEqual("5935-KG", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Markmonitor", response.TechnicalContact.Name);
            Assert.AreEqual("+12083895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+12083895771", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(1, response.TechnicalContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place Boise, ID 83704", response.TechnicalContact.Address[0]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns4.google.com", response.NameServers[2]);

            Assert.AreEqual(26, response.FieldsParsed);
        }
    }
}
