using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Isnic.Is.Is
{
    [TestFixture]
    public class IsParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.isnic.is", "is", "not_found.txt");
            var response = parser.Parse("whois.isnic.is", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.isnic.is/is/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.is", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.isnic.is", "is", "found.txt");
            var response = parser.Parse("whois.isnic.is", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found04", response.TemplateName);

            Assert.AreEqual("google.is", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2002, 05, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 05, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Ampitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, California 94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("GI58-IS", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);
            Assert.AreEqual(new DateTime(2012, 10, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.AdminContact.Created);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("MTC2-IS", response.BillingContact.RegistryId);
            Assert.AreEqual("Markmonitor Tech Contact", response.BillingContact.Name);
            Assert.AreEqual("+1 208 3895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);
            Assert.AreEqual(new DateTime(2004, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.BillingContact.Created);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("391 N. Ancestor Pl.", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise, ID 83704", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("MTC2-IS", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Markmonitor Tech Contact", response.TechnicalContact.Name);
            Assert.AreEqual("+1 208 3895740", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);
            Assert.AreEqual(new DateTime(2004, 07, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.TechnicalContact.Created);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("391 N. Ancestor Pl.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Boise, ID 83704", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


             // ZoneContact Details
            Assert.AreEqual("AG49-IS", response.ZoneContact.RegistryId);
            Assert.AreEqual("Amit Garg", response.ZoneContact.Name);
            Assert.AreEqual("+1 650 3300100", response.ZoneContact.TelephoneNumber);
            Assert.AreEqual("+1 650 6188571", response.ZoneContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.ZoneContact.Email);
            Assert.AreEqual(new DateTime(2004, 10, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.ZoneContact.Created);

             // ZoneContact Address
            Assert.AreEqual(4, response.ZoneContact.Address.Count);
            Assert.AreEqual("Google Inc.", response.ZoneContact.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.ZoneContact.Address[1]);
            Assert.AreEqual("Mountain View, CA 94043", response.ZoneContact.Address[2]);
            Assert.AreEqual("US", response.ZoneContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            Assert.AreEqual(39, response.FieldsParsed);
        }
    }
}
