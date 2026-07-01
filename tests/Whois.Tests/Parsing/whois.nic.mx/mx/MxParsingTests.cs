using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mx.Mx
{
    [TestFixture]
    public class MxParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.mx", "mx", "found.txt");
            var response = parser.Parse("whois.nic.mx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.mx/mx/Found", response.TemplateName);

            Assert.AreEqual("mpsnet.net.mx", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("NIC Mexico", response.Registrar.Name);
            Assert.AreEqual("http://www.nic.mx", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2009, 03, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1997, 04, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2011, 04, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("MPSNet Dominios", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Mexico", response.Registrant.Address[0]);
            Assert.AreEqual("Distrito Federal", response.Registrant.Address[1]);
            Assert.AreEqual("Mexico", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Internet Engine S.A de C.V", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("D.F.", response.AdminContact.Address[0]);
            Assert.AreEqual("Distrito Federal", response.AdminContact.Address[1]);
            Assert.AreEqual("Mexico", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("Internet Engine S.A de C.V", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("D.F.", response.BillingContact.Address[0]);
            Assert.AreEqual("Distrito Federal", response.BillingContact.Address[1]);
            Assert.AreEqual("Mexico", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Internet Engine S.A de C.V", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("D.F.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Distrito Federal", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Mexico", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(1, response.NameServers.Count);
            Assert.AreEqual("dns1.mpsnet.net.mx", response.NameServers[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.mx", "mx", "not_found.txt");
            var response = parser.Parse("whois.nic.mx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.mx/mx/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.mx", "mx", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.mx", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.mx/mx/Found", response.TemplateName);

            Assert.AreEqual("google.mx", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com/", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2013, 07, 29, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 05, 12, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2016, 05, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Mountain View", response.Registrant.Address[0]);
            Assert.AreEqual("California", response.Registrant.Address[1]);
            Assert.AreEqual("United States", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Google Inc.", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[0]);
            Assert.AreEqual("California", response.AdminContact.Address[1]);
            Assert.AreEqual("United States", response.AdminContact.Address[2]);


             // BillingContact Details
            Assert.AreEqual("MarkMonitor", response.BillingContact.Name);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("Boise", response.BillingContact.Address[0]);
            Assert.AreEqual("Idaho", response.BillingContact.Address[1]);
            Assert.AreEqual("United States", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[0]);
            Assert.AreEqual("California", response.TechnicalContact.Address[1]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[2]);


            Assert.AreEqual(23, response.FieldsParsed);
        }
    }
}
