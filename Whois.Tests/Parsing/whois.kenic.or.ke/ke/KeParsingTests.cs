using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Kenic.Or.Ke.Ke
{
    [TestFixture]
    public class KeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "not_found.txt");
            var response = parser.Parse("whois.kenic.or.ke", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kenic.or.ke/ke/Found", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ke", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Not Registered", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "invalid.txt");
            var response = parser.Parse("whois.kenic.or.ke", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Invalid, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kenic.or.ke/ke/Found", response.TemplateName);

            Assert.AreEqual("www.housekenya.co.ke", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("This WHOIS server does not have any records for that zone.", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.kenic.or.ke", "ke", "found.txt");
            var response = parser.Parse("whois.kenic.or.ke", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.kenic.or.ke/ke/Found", response.TemplateName);

            Assert.AreEqual("google.co.ke", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Afriregister Limited", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 12, 16, 09, 48, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 04, 17, 21, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 12, 31, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DNS Admin", response.Registrant.Name);
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(1, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);


             // BillingContact Details
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("391 N. Ancestor Place", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise, ID 83704", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);

            Assert.AreEqual(37, response.FieldsParsed);
         }
    }
}
