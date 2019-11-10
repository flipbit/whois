using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Netcom.Cm.Cm
{
    [TestFixture]
    public class CmParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "not_found.txt");
            var response = parser.Parse("whois.netcom.cm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.netcom.cm/cm/Found", response.TemplateName);

            Assert.AreEqual("u34jedzcq.cm", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Not Registered", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "found.txt");
            var response = parser.Parse("whois.netcom.cm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.netcom.cm/cm/Found", response.TemplateName);

            Assert.AreEqual("google.cm", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 09, 20, 16, 47, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 10, 07, 09, 02, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 07, 09, 02, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Organization);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("Google Inc.", response.AdminContact.Organization);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View, CA 94043", response.AdminContact.Address[1]);
            Assert.AreEqual("US", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("MarkMonitor Inc.", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor Inc.", response.BillingContact.Organization);
            Assert.AreEqual("ccopsbilling@markmonitor.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise, ID 83704", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.TechnicalContact.Address[0]);
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

            Assert.AreEqual(34, response.FieldsParsed);
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("whois.netcom.cm", "cm", "suspended.txt");
            var response = parser.Parse("whois.netcom.cm", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Suspended, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.netcom.cm/cm/Found", response.TemplateName);

            Assert.AreEqual("imdb.cm", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Registrar ANTIC", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 01, 24, 08, 17, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 08, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 08, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("cm.legacy@netcom.cm", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("Camtel | ANTIC l Legacy-Escrow", response.AdminContact.Name);
            Assert.AreEqual("cm.legacy@netcom.cm", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("Camtel | ANTIC l Legacy-Escrow", response.BillingContact.Name);
            Assert.AreEqual("cm.legacy@netcom.cm", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Camtel | ANTIC l Legacy-Escrow", response.TechnicalContact.Name);
            Assert.AreEqual("cm.legacy@netcom.cm", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.refinedhosting.net", response.NameServers[0]);
            Assert.AreEqual("ns2.refinedhosting.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Suspended", response.DomainStatus[0]);

            Assert.AreEqual(16, response.FieldsParsed);
        }
    }
}
