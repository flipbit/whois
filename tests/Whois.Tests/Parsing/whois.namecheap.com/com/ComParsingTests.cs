using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Namecheap.Com.Com
{
    [TestFixture]
    public class ComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.namecheap.com", "com", "found.txt");
            var response = parser.Parse("whois.namecheap.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("slavichy.com", response.DomainName.ToString());
            Assert.AreEqual("2175421662_DOMAIN_COM-VRSN", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("NAMECHEAP INC", response.Registrar.Name);
            Assert.AreEqual("1068", response.Registrar.IanaId);
            Assert.AreEqual("http://www.namecheap.com", response.Registrar.Url);
            Assert.AreEqual("abuse@namecheap.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+1.6613102107", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2019, 09, 17, 10, 07, 38, 810, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2017, 10, 17, 17, 37, 03, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2020, 10, 17, 17, 37, 03, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("WhoisGuard Protected", response.Registrant.Name);
            Assert.AreEqual("+507.8365503", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+51.17057182", response.Registrant.FaxNumber);
            Assert.AreEqual("2d053ce12e12426e89791ea5f9616208.protect@whoisguard.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("P.O. Box 0823-03411", response.Registrant.Address[0]);
            Assert.AreEqual("Panama", response.Registrant.Address[1]);
            Assert.AreEqual("Panama", response.Registrant.Address[2]);
            Assert.AreEqual("PA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("WhoisGuard Protected", response.AdminContact.Name);
            Assert.AreEqual("+507.8365503", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+51.17057182", response.AdminContact.FaxNumber);
            Assert.AreEqual("2d053ce12e12426e89791ea5f9616208.protect@whoisguard.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("P.O. Box 0823-03411", response.AdminContact.Address[0]);
            Assert.AreEqual("Panama", response.AdminContact.Address[1]);
            Assert.AreEqual("Panama", response.AdminContact.Address[2]);
            Assert.AreEqual("PA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("WhoisGuard Protected", response.TechnicalContact.Name);
            Assert.AreEqual("+507.8365503", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+51.17057182", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("2d053ce12e12426e89791ea5f9616208.protect@whoisguard.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("P.O. Box 0823-03411", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Panama", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Panama", response.TechnicalContact.Address[2]);
            Assert.AreEqual("PA", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("heather.ns.cloudflare.com", response.NameServers[0]);
            Assert.AreEqual("josh.ns.cloudflare.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(46, response.FieldsParsed);
        }
    }
}
