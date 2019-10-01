using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Comlaude.Com.Com
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
        public void Test_found_adobe_com()
        {
            var sample = SampleReader.Read("whois.comlaude.com", "com", "adobe.com.txt");
            
            var response = parser.Parse("whoiscomlaude.com", sample);

            Assert.AreEqual("adobe.com", response.DomainName);
            Assert.AreEqual("4364022_DOMAIN_COM-VRSN", response.RegistryDomainId);
            Assert.AreEqual("whois.comlaude.com", response.Registrar.WhoisServerUrl);
            Assert.AreEqual("http://www.comlaude.com", response.Registrar.Url);
            Assert.AreEqual(new DateTime(2018, 10, 18, 17, 9, 58), response.Updated.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(1986, 11, 17, 05, 0, 00), response.Registered.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2019, 05, 17, 00, 0, 00), response.Expiration.Value.ToUniversalTime());
            Assert.AreEqual("NOM-IQ Ltd dba Com Laude", response.Registrar.Name);
            Assert.AreEqual("470", response.Registrar.IanaId);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[0]);
            Assert.AreEqual("serverDeleteProhibited", response.DomainStatus[1]);
            Assert.AreEqual("serverTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("serverUpdateProhibited", response.DomainStatus[3]);
            Assert.AreEqual("Domain Administrator", response.Registrant.Name);
            Assert.AreEqual("Adobe Inc.", response.Registrant.Organization);
            Assert.AreEqual("345 Park Avenue", response.Registrant.Address[0]);
            Assert.AreEqual("San Jose", response.Registrant.Address[1]);
            Assert.AreEqual("California", response.Registrant.Address[2]);
            Assert.AreEqual("95110", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);
            Assert.AreEqual("+1.4085366000", response.Registrant.TelephoneNumber);
            Assert.AreEqual(null, response.Registrant.TelephoneNumberExt);
            Assert.AreEqual(null, response.Registrant.FaxNumber);
            Assert.AreEqual(null, response.Registrant.FaxNumberExt);
            Assert.AreEqual("dns-admin@adobe.com", response.Registrant.Email);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);
            Assert.AreEqual("Adobe Inc.", response.AdminContact.Organization);
            Assert.AreEqual("345 Park Avenue", response.AdminContact.Address[0]);
            Assert.AreEqual("San Jose", response.AdminContact.Address[1]);
            Assert.AreEqual("California", response.AdminContact.Address[2]);
            Assert.AreEqual("95110", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);
            Assert.AreEqual("+1.4085366000", response.AdminContact.TelephoneNumber);
            Assert.AreEqual(null, response.AdminContact.TelephoneNumberExt);
            Assert.AreEqual(null, response.AdminContact.FaxNumber);
            Assert.AreEqual(null, response.AdminContact.FaxNumberExt);
            Assert.AreEqual("dns-admin@adobe.com", response.AdminContact.Email);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
            Assert.AreEqual("REDACTED FOR PRIVACY", response.TechnicalContact.Address[4]);
            Assert.AreEqual(null, response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual(null, response.TechnicalContact.TelephoneNumberExt);
            Assert.AreEqual(null, response.TechnicalContact.FaxNumber);
            Assert.AreEqual(null, response.TechnicalContact.FaxNumberExt);
            Assert.AreEqual("adobe.com-Tech@anonymised.email", response.TechnicalContact.Email);

            Assert.AreEqual(7, response.NameServers.Count);
            Assert.AreEqual("a1-217.akam.net", response.NameServers[0]);
            Assert.AreEqual("a10-64.akam.net", response.NameServers[1]);
            Assert.AreEqual("a13-65.akam.net", response.NameServers[2]);
            Assert.AreEqual("a26-66.akam.net", response.NameServers[3]);
            Assert.AreEqual("a28-67.akam.net", response.NameServers[4]);
            Assert.AreEqual("a7-64.akam.net", response.NameServers[5]);
            Assert.AreEqual("adobe-dns-01.adobe.com", response.NameServers[6]);

            Assert.AreEqual("Unsigned Delegation", response.DnsSecStatus);
            Assert.AreEqual("abuse@comlaude.com", response.Registrar.AbuseEmail);
            Assert.AreEqual("+44.2074218250", response.Registrar.AbuseTelephoneNumber);
        }
    }
}
