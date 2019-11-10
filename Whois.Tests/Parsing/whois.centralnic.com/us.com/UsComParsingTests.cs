using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UsCom
{
    [TestFixture]
    public class UsComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "us.com", "not_found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.centralnic.com", "us.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("college.us.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO275307", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2012, 1, 16, 16, 27, 26, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 10, 20, 10, 3, 28, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 10, 20, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1044037", response.Registrant.RegistryId);
            Assert.AreEqual("Vantage Media Corporation", response.Registrant.Name);
            Assert.AreEqual("+1.3102196200", response.Registrant.TelephoneNumber);
            Assert.AreEqual("domainadmin@vantagemedia.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("2101 Rosecrans Ave.", response.Registrant.Address[0]);
            Assert.AreEqual("Suite 2000", response.Registrant.Address[1]);
            Assert.AreEqual("90245", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("H143205", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("Vantage Media LLC", response.AdminContact.Organization);
            Assert.AreEqual("+1.3102196200", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("domainadmin@vantagemedia.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("2101 Rosecrans Ave.", response.AdminContact.Address[0]);
            Assert.AreEqual("Suite 2000", response.AdminContact.Address[1]);
            Assert.AreEqual("90245", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("H143205", response.BillingContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.BillingContact.Name);
            Assert.AreEqual("Vantage Media LLC", response.BillingContact.Organization);
            Assert.AreEqual("+1.3102196200", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.8665897214", response.BillingContact.FaxNumber);
            Assert.AreEqual("domainadmin@vantagemedia.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("2101 Rosecrans Ave.", response.BillingContact.Address[0]);
            Assert.AreEqual("90245", response.BillingContact.Address[1]);
            Assert.AreEqual("US", response.BillingContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("H143205", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.TechnicalContact.Name);
            Assert.AreEqual("Vantage Media LLC", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.3102196200", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("domainadmin@vantagemedia.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("2101 Rosecrans Ave.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Suite 2000", response.TechnicalContact.Address[1]);
            Assert.AreEqual("90245", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.p17.dynect.net", response.NameServers[0]);
            Assert.AreEqual("ns2.p17.dynect.net", response.NameServers[1]);
            Assert.AreEqual("ns3.p17.dynect.net", response.NameServers[2]);
            Assert.AreEqual("ns4.p17.dynect.net", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(47, response.FieldsParsed);
        }
    }
}
