using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.La.La
{
    [TestFixture]
    public class LaParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.la", "la", "found.txt");
            var response = parser.Parse("whois.nic.la", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("plasticsurgery.la", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO469366", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("+49.68949396850", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2010, 03, 31, 12, 43, 59, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 02, 02, 01, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2017, 02, 02, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("P-1901109", response.Registrant.RegistryId);
            Assert.AreEqual("Jay Granzow", response.Registrant.Name);
            Assert.AreEqual("Jay Granzow", response.Registrant.Organization);
            Assert.AreEqual("+1.3105304200", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.3105301652", response.Registrant.FaxNumber);
            Assert.AreEqual("jwgranzow@gmail.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("22930 Crenshaw Blvd. Suite D", response.Registrant.Address[0]);
            Assert.AreEqual("Torrance", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("90505", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("P-1901109", response.AdminContact.RegistryId);
            Assert.AreEqual("Jay Granzow", response.AdminContact.Name);
            Assert.AreEqual("Jay Granzow", response.AdminContact.Organization);
            Assert.AreEqual("+1.3105304200", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.3105301652", response.AdminContact.FaxNumber);
            Assert.AreEqual("jwgranzow@gmail.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("22930 Crenshaw Blvd. Suite D", response.AdminContact.Address[0]);
            Assert.AreEqual("Torrance", response.AdminContact.Address[1]);
            Assert.AreEqual("CA", response.AdminContact.Address[2]);
            Assert.AreEqual("90505", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("P-1901109", response.BillingContact.RegistryId);
            Assert.AreEqual("Jay Granzow", response.BillingContact.Name);
            Assert.AreEqual("Jay Granzow", response.BillingContact.Organization);
            Assert.AreEqual("+1.3105304200", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.3105301652", response.BillingContact.FaxNumber);
            Assert.AreEqual("jwgranzow@gmail.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("22930 Crenshaw Blvd. Suite D", response.BillingContact.Address[0]);
            Assert.AreEqual("Torrance", response.BillingContact.Address[1]);
            Assert.AreEqual("CA", response.BillingContact.Address[2]);
            Assert.AreEqual("90505", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("P-9055753", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Jay Granzow", response.TechnicalContact.Name);
            Assert.AreEqual("Jay Granzow", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.3105304200", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.3105301652", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("jwgranzow@yahoo.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("22930 Crenshaw Blvd. Suite D", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Torrance", response.TechnicalContact.Address[1]);
            Assert.AreEqual("CA", response.TechnicalContact.Address[2]);
            Assert.AreEqual("90505", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.slcit.com", response.NameServers[0]);
            Assert.AreEqual("ns1.slcit.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("TRANSFER PROHIBITED", response.DomainStatus[0]);
            Assert.AreEqual("RENEW PERIOD", response.DomainStatus[1]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(56, response.FieldsParsed);
        }

        [Test]
        public void Test_other_status_single()
        {
            var sample = SampleReader.Read("whois.nic.la", "la", "other_status_single.txt");
            var response = parser.Parse("whois.nic.la", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.la", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO471480", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("+44.8700170900", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2009, 09, 15, 16, 48, 47, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 07, 18, 01, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2010, 07, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("ndn-96955", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc", response.Registrant.Name);
            Assert.AreEqual("Google Inc", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.65067188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("Ca", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("ndn-96955", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc", response.AdminContact.Name);
            Assert.AreEqual("Google Inc", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.65067188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("Ca", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("ndn-24412", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Billing", response.BillingContact.Name);
            Assert.AreEqual("Markmonitor", response.BillingContact.Organization);
            Assert.AreEqual("+1.20838957", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("10400 Overland Rd.", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("ID", response.BillingContact.Address[2]);
            Assert.AreEqual("83709", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("ndn-96955", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.65067188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ca", response.TechnicalContact.Address[2]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);

            Assert.AreEqual(55, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.la", "la", "not_found.txt");
            var response = parser.Parse("whois.nic.la", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.la", "la", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.la", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.la", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO471480", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("1564", response.Registrar.IanaId);
            Assert.AreEqual("020 33 88 0600", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 08, 01, 15, 09, 21, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2002, 07, 18, 01, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 07, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("ndn-96955", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc", response.Registrant.Name);
            Assert.AreEqual("Google Inc", response.Registrant.Organization);
            Assert.AreEqual("+1.6502530000", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1.65067188571", response.Registrant.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("Ca", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


             // AdminContact Details
            Assert.AreEqual("ndn-96955", response.AdminContact.RegistryId);
            Assert.AreEqual("Google Inc", response.AdminContact.Name);
            Assert.AreEqual("Google Inc", response.AdminContact.Organization);
            Assert.AreEqual("+1.6502530000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.65067188571", response.AdminContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("Ca", response.AdminContact.Address[2]);
            Assert.AreEqual("94043", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // BillingContact Details
            Assert.AreEqual("LAREG-4FB6D5852C61F054", response.BillingContact.RegistryId);
            Assert.AreEqual("MarkMonitor, Inc.", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor, Inc.", response.BillingContact.Organization);
            Assert.AreEqual("+1.2083895740", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.BillingContact.FaxNumber);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("ID", response.BillingContact.Address[2]);
            Assert.AreEqual("83704", response.BillingContact.Address[3]);
            Assert.AreEqual("US", response.BillingContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("ndn-96955", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Google Inc", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.65067188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Ca", response.TechnicalContact.Address[2]);
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
            Assert.AreEqual(59, response.FieldsParsed);
        }
    }
}
