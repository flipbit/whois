using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.RuCom
{
    [TestFixture]
    public class RuComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "ru.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "ru.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("srk.ru.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO450826", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2012, 7, 10, 8, 16, 19, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2006, 7, 31, 10, 6, 4, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 7, 31, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1037013", response.Registrant.RegistryId);
            Assert.AreEqual("Anthony Lloyd, SRK Consulting (UK) Limited", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("5th Floor", response.Registrant.Address[0]);
            Assert.AreEqual("Churchill House", response.Registrant.Address[1]);
            Assert.AreEqual("Cardiff", response.Registrant.Address[2]);
            Assert.AreEqual("CF10 2HH", response.Registrant.Address[3]);
            Assert.AreEqual("GB", response.Registrant.Address[4]);

            Assert.AreEqual("+44.2920348150", response.Registrant.TelephoneNumber);
            Assert.AreEqual("alloyd@srk.co.uk", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("H265405", response.AdminContact.RegistryId);
            Assert.AreEqual("Anthony Lloyd", response.AdminContact.Name);
            Assert.AreEqual("SRK Consulting (UK) Limited", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("5th Floor", response.AdminContact.Address[0]);
            Assert.AreEqual("Churchill House", response.AdminContact.Address[1]);
            Assert.AreEqual("Cardiff", response.AdminContact.Address[2]);
            Assert.AreEqual("CF10 2HH", response.AdminContact.Address[3]);
            Assert.AreEqual("GB", response.AdminContact.Address[4]);

            Assert.AreEqual("+44.2920348150", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("alloyd@srk.co.uk", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("H265406", response.BillingContact.RegistryId);
            Assert.AreEqual("A R Lloyd", response.BillingContact.Name);
            Assert.AreEqual("SRK Consulting (UK) Limited", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(3, response.BillingContact.Address.Count);
            Assert.AreEqual("Windsor Court", response.BillingContact.Address[0]);
            Assert.AreEqual("CF10 3BX", response.BillingContact.Address[1]);
            Assert.AreEqual("GB", response.BillingContact.Address[2]);

            Assert.AreEqual("+44.2920348150", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("alloyd@srk.co.uk", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("H265405", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Anthony Lloyd", response.TechnicalContact.Name);
            Assert.AreEqual("SRK Consulting (UK) Limited", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("5th Floor", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Churchill House", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Cardiff", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CF10 2HH", response.TechnicalContact.Address[3]);
            Assert.AreEqual("GB", response.TechnicalContact.Address[4]);

            Assert.AreEqual("+44.2920348150", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("alloyd@srk.co.uk", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns7.zoneedit.com", response.NameServers[0]);
            Assert.AreEqual("ns12.zoneedit.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(47, response.FieldsParsed);
        }
    }
}
