using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Im.Im
{
    [TestFixture]
    public class ImParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.im", "im", "not_found.txt");
            var response = parser.Parse("whois.nic.im", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.im/im/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.im", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.im", "im", "found.txt");
            var response = parser.Parse("whois.nic.im", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.im/im/Found", response.TemplateName);

            Assert.AreEqual("google.im", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Reseller - Mark Monitor", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 08, 03, 23, 59, 52, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Address", response.Registrant.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[1]);
            Assert.AreEqual("Mountain View, CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("Google Inc. Domain Admin", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Address", response.AdminContact.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[1]);
            Assert.AreEqual("Mountain View, CA", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("United States", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("Mr Domain Administrator", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("Address", response.BillingContact.Address[0]);
            Assert.AreEqual("Emerald Tech Center", response.BillingContact.Address[1]);
            Assert.AreEqual("391 N. Ancestor Pl", response.BillingContact.Address[2]);
            Assert.AreEqual("Boise, ID", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Mr Domain Administrator", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Address", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Emerald Tech Center", response.TechnicalContact.Address[1]);
            Assert.AreEqual("391 N. Ancestor Pl", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Boise, ID", response.TechnicalContact.Address[3]);
            Assert.AreEqual("83704", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(30, response.FieldsParsed);
        }
    }
}
