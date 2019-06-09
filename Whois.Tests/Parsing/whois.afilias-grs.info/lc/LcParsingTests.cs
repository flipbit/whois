using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Lc
{
    [TestFixture]
    public class LcParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.afilias-grs.info", "lc", "not_found.txt");
            var response = parser.Parse("whois.afilias-grs.info", "lc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.NotFound, response.Status);

            Assert.AreEqual(1, response.FieldsParsed);
            Assert.AreEqual("generic/tld/NotFound001", response.TemplateName);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.afilias-grs.info", "lc", "found.txt");
            var response = parser.Parse("whois.afilias-grs.info", "lc", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            Assert.AreEqual(35, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("nic.lc", response.DomainName);
            Assert.AreEqual("D946482-LRCC", response.RegistryDomainId);

            Assert.AreEqual("NicLc Registrar (R144-LRCC)", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2008, 12, 8, 19, 25, 9), response.Updated);
            Assert.AreEqual(new DateTime(2002, 12, 8, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2009, 12, 8, 0, 0, 0), response.Expiration);
            Assert.AreEqual("LC-54921", response.Registrant.RegistryId);
            Assert.AreEqual("Nic LC Admin", response.Registrant.Name);
            Assert.AreEqual("Nic LC", response.Registrant.Organization);

            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Castries", response.Registrant.Address[0]);
            Assert.AreEqual("Not Provided", response.Registrant.Address[1]);
            Assert.AreEqual("Not Provided", response.Registrant.Address[2]);
            Assert.AreEqual("LC", response.Registrant.Address[3]);

            Assert.AreEqual("+758.4520220", response.Registrant.TelephoneNumber);
            Assert.AreEqual("nic@nic.lc", response.Registrant.Email);

            Assert.AreEqual("LC-51893", response.AdminContact.RegistryId);
            Assert.AreEqual("Nic LC Hostmaster", response.AdminContact.Name);
            Assert.AreEqual("Nic LC", response.AdminContact.Organization);

            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Castries", response.AdminContact.Address[0]);
            Assert.AreEqual("Not Provided", response.AdminContact.Address[1]);
            Assert.AreEqual("Not Provided", response.AdminContact.Address[2]);
            Assert.AreEqual("LC", response.AdminContact.Address[3]);

            Assert.AreEqual("hostmaster@nic.lc", response.AdminContact.Email);

            Assert.AreEqual("LC-53407", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Nic LC Technical", response.TechnicalContact.Name);
            Assert.AreEqual("Nic LC", response.TechnicalContact.Organization);

            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Castries", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Not Provided", response.TechnicalContact.Address[1]);
            Assert.AreEqual("LC", response.TechnicalContact.Address[2]);

            Assert.AreEqual("+758.4520220", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("technical@nic.lc", response.TechnicalContact.Email);


            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.nic.ag", response.NameServers[0]);
            Assert.AreEqual("ns.patricklay.com", response.NameServers[1]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("OK", response.DomainStatus[0]);
        }
    }
}
