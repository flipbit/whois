using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Pandi.Or.Id.Id
{
    [TestFixture]
    public class IdParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.pandi.or.id", "id", "not_found.txt");
            var response = parser.Parse("whois.pandi.or.id", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.pandi.or.id", "id", "found.txt");
            var response = parser.Parse("whois.pandi.or.id", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.co.id", response.DomainName.ToString());
            Assert.AreEqual("PANDI-DO246796", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("0274882257", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 09, 20, 23, 24, 51, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 12, 18, 13, 33, 21, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 09, 01, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("0123459P2ZC", response.Registrant.RegistryId);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("PT Google Indonesia", response.Registrant.Organization);
            Assert.AreEqual("+62.2123584400", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+62.2123584400", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Menara BCA Grand Indonesia", response.Registrant.Address[0]);
            Assert.AreEqual("Regus Grand Indonesia", response.Registrant.Address[1]);
            Assert.AreEqual("Jakarta", response.Registrant.Address[2]);
            Assert.AreEqual("Jakarta", response.Registrant.Address[3]);
            Assert.AreEqual("10310", response.Registrant.Address[4]);
            Assert.AreEqual("ID", response.Registrant.Address[5]);


             // AdminContact Details
            Assert.AreEqual("0123459P2ZC", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("PT Google Indonesia", response.AdminContact.Organization);
            Assert.AreEqual("+62.2123584400", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+62.2123584400", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("Menara BCA Grand Indonesia", response.AdminContact.Address[0]);
            Assert.AreEqual("Regus Grand Indonesia", response.AdminContact.Address[1]);
            Assert.AreEqual("Jakarta", response.AdminContact.Address[2]);
            Assert.AreEqual("Jakarta", response.AdminContact.Address[3]);
            Assert.AreEqual("10310", response.AdminContact.Address[4]);
            Assert.AreEqual("ID", response.AdminContact.Address[5]);


             // BillingContact Details
            Assert.AreEqual("0120505a1pl", response.BillingContact.RegistryId);
            Assert.AreEqual("CCOPS Billing", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895741", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("JL.Hang Kesturi KM 4 Kabil Indus", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("ID", response.BillingContact.Address[2]);
            Assert.AreEqual("83704", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("01234616RFG", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.65030000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.65030001", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(60, response.FieldsParsed);
        }
    }
}
