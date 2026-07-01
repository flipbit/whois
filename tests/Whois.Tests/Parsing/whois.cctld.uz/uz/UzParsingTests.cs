using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cctld.Uz.Uz
{
    [TestFixture]
    public class UzParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "reserved.txt");
            var response = parser.Parse("whois.cctld.uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cctld.uz/uz/Reserved", response.TemplateName);

            Assert.AreEqual("cctld.uz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("UZINFOCOM", response.Registrar.Name);
            Assert.AreEqual("http://www.cctld.uz/", response.Registrar.Url);
            Assert.AreEqual("www.whois.uz", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2005, 5, 1, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2005, 5, 1, 0, 0, 0), response.Registered);

             // Registrant Details
            Assert.AreEqual("Rakhimov D. K.	(info [at] uzinfocom.uz)", response.Registrant.Name);
            Assert.AreEqual("not.defined.", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("A.Navoi str., 28 B", response.Registrant.Address[0]);
            Assert.AreEqual("Tashkent", response.Registrant.Address[1]);
            Assert.AreEqual("Uzbekistan, 100011", response.Registrant.Address[2]);
            Assert.AreEqual("UZ", response.Registrant.Address[3]);

            Assert.AreEqual("+998 71 238-42-00", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+998 71 238-42-48", response.Registrant.FaxNumber);


             // AdminContact Details
            Assert.AreEqual("Djuraev I.D.	(info [at] uzinfocom.uz)", response.AdminContact.Name);
            Assert.AreEqual("Center UZINFOCOM", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("A.Navoi str., 28 B", response.AdminContact.Address[0]);
            Assert.AreEqual("Tashkent", response.AdminContact.Address[1]);
            Assert.AreEqual("Uzbekistan, 100011", response.AdminContact.Address[2]);
            Assert.AreEqual("UZ", response.AdminContact.Address[3]);

            Assert.AreEqual("+998 71 238-41-48", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+998 71 238-42-48", response.AdminContact.FaxNumber);

             // BillingContact Details
            Assert.AreEqual("Karnaushevskaya A.K.	(info [at] uzinfocom.uz)", response.BillingContact.Name);
            Assert.AreEqual("Center UZINFOCOM", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("A.Navoi str., 28 B", response.BillingContact.Address[0]);
            Assert.AreEqual("Tashkent", response.BillingContact.Address[1]);
            Assert.AreEqual("Uzbekistan, 100011", response.BillingContact.Address[2]);
            Assert.AreEqual("UZ", response.BillingContact.Address[3]);

            Assert.AreEqual("+998 71 238-42-00", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+998 71 238-42-48", response.BillingContact.FaxNumber);

             // TechnicalContact Details
            Assert.AreEqual("Deykhin V.V.	(info [at] uzinfocom.uz)", response.TechnicalContact.Name);
            Assert.AreEqual("Center UZINFOCOM", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("A.Navoi str., 28 B", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Tashkent", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Uzbekistan,  100011", response.TechnicalContact.Address[2]);
            Assert.AreEqual("UZ", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+998 71 238-42-45", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+998 71 238-42-48", response.TechnicalContact.FaxNumber);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns.uz", response.NameServers[0]);
            Assert.AreEqual("ns2.uz", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("RESERVED", response.DomainStatus[0]);

            Assert.AreEqual(42, response.FieldsParsed);
            AssertWriter.Write(response);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "not_found.txt");
            var response = parser.Parse("whois.cctld.uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cctld.uz/uz/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.uz", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.cctld.uz", "uz", "found_status_registered.txt");
            var response = parser.Parse("whois.cctld.uz", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.cctld.uz/uz/Found", response.TemplateName);

            Assert.AreEqual("google.uz", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("TOMAS", response.Registrar.Name);
            Assert.AreEqual("http://www.cctld.uz/", response.Registrar.Url);
            Assert.AreEqual("www.whois.uz", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2010, 3, 26, 0, 0, 0), response.Updated);
            Assert.AreEqual(new DateTime(2006, 4, 13, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2011, 5, 1, 0, 0, 0), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DNS Admin	(dns-admin [at] google.com)", response.Registrant.Name);
            Assert.AreEqual("Google Inc", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("US, 94043", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);

            Assert.AreEqual("+1 6503300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+1 6506181499", response.Registrant.FaxNumber);

             // AdminContact Details
            Assert.AreEqual("DNS Admin	(dns-admin [at] google.com)", response.AdminContact.Name);
            Assert.AreEqual("Google Inc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("2400 E Bayshore Pkwy", response.AdminContact.Address[0]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[1]);
            Assert.AreEqual("US, 94043", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);

            Assert.AreEqual("+1 6503300100", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1 6506181499", response.AdminContact.FaxNumber);

             // BillingContact Details
            Assert.AreEqual("Kevin Pearl	(ccops [at] markmonitor.com)", response.BillingContact.Name);
            Assert.AreEqual("MarkMonitor", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("10400 Overland Road PMB 155", response.BillingContact.Address[0]);
            Assert.AreEqual("Boise", response.BillingContact.Address[1]);
            Assert.AreEqual("US, 83709", response.BillingContact.Address[2]);
            Assert.AreEqual("US", response.BillingContact.Address[3]);

            Assert.AreEqual("+1 208 389 5798", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1 208 389 5771", response.BillingContact.FaxNumber);

             // TechnicalContact Details
            Assert.AreEqual("DNS Admin	(dns-admin [at] google.com)", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2400 E Bayshore Pkwy", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US, 94043", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+1 6503300100", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1 6506181499", response.TechnicalContact.FaxNumber);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(43, response.FieldsParsed);
        }
    }
}
