using System;
using System.IO;
using NUnit.Framework;
using Whois.Models;

namespace Whois.Visitors
{
    [TestFixture]
    public class PatternExtractorVisitorTest
    {
        private PatternExtractorVisitor visitor;

        [SetUp]
        public void SetUp()
        {
            visitor = new PatternExtractorVisitor();
        }

        [Test]
        public void TestParseRecord()
        {
            var sample = File.ReadAllText("..\\..\\..\\Samples\\Domains\\adobe.com.txt");

            var state = new LookupState
            {
                Response = new WhoisResponse(sample),
                Options = new WhoisOptions {  ParseWhoisResponse = true }
            };
            
            visitor.Visit(state);

            var record = state.Response.ParsedResponse;

            Assert.AreEqual("adobe.com", record.DomainName);
            Assert.AreEqual("4364022_DOMAIN_COM-VRSN", record.RegistryDomainId);
            Assert.AreEqual("whois.comlaude.com", record.Registrar.WhoisServerUrl);
            Assert.AreEqual("http://www.comlaude.com", record.Registrar.Url);
            Assert.AreEqual(new DateTime(2018, 10, 18, 17, 9, 58), record.Updated.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(1986, 11, 17, 05, 0, 00), record.Registered.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2019, 05, 17, 00, 0, 00), record.Expiration.Value.ToUniversalTime());
            Assert.AreEqual("NOM-IQ Ltd dba Com Laude", record.Registrar.Name);
            Assert.AreEqual("470", record.Registrar.IanaId);
            Assert.AreEqual("clientUpdateProhibited https://www.icann.org/epp#clientUpdateProhibited", record.DomainStatus[0]);
            Assert.AreEqual("serverDeleteProhibited https://www.icann.org/epp#serverDeleteProhibited", record.DomainStatus[1]);
            Assert.AreEqual("serverTransferProhibited https://www.icann.org/epp#serverTransferProhibited", record.DomainStatus[2]);
            Assert.AreEqual("serverUpdateProhibited https://www.icann.org/epp#serverUpdateProhibited", record.DomainStatus[3]);
            Assert.AreEqual("Domain Administrator", record.Registrant.Name);
            Assert.AreEqual("Adobe Inc.", record.Registrant.Organization);
            Assert.AreEqual("345 Park Avenue", record.Registrant.Address[0]);
            Assert.AreEqual("San Jose", record.Registrant.Address[1]);
            Assert.AreEqual("California", record.Registrant.Address[2]);
            Assert.AreEqual("95110", record.Registrant.Address[3]);
            Assert.AreEqual("US", record.Registrant.Address[4]);
            Assert.AreEqual("+1.4085366000", record.Registrant.TelephoneNumber);
            Assert.AreEqual("", record.Registrant.TelephoneNumberExt);
            Assert.AreEqual("", record.Registrant.FaxNumber);
            Assert.AreEqual("", record.Registrant.FaxNumberExt);
            Assert.AreEqual("dns-admin@adobe.com", record.Registrant.Email);
            Assert.AreEqual("Domain Administrator", record.AdminContact.Name);
            Assert.AreEqual("Adobe Inc.", record.AdminContact.Organization);
            Assert.AreEqual("345 Park Avenue", record.AdminContact.Address[0]);
            Assert.AreEqual("San Jose", record.AdminContact.Address[1]);
            Assert.AreEqual("California", record.AdminContact.Address[2]);
            Assert.AreEqual("95110", record.AdminContact.Address[3]);
            Assert.AreEqual("US", record.AdminContact.Address[4]);
            Assert.AreEqual("+1.4085366000", record.AdminContact.TelephoneNumber);
            Assert.AreEqual("", record.AdminContact.TelephoneNumberExt);
            Assert.AreEqual("", record.AdminContact.FaxNumber);
            Assert.AreEqual("", record.AdminContact.FaxNumberExt);
            Assert.AreEqual("dns-admin@adobe.com", record.AdminContact.Email);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Name);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Organization);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Address[0]);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Address[1]);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Address[2]);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Address[3]);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.Address[4]);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.TelephoneNumberExt);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.FaxNumber);
            Assert.AreEqual("REDACTED FOR PRIVACY", record.TechnicalContact.FaxNumberExt);
            Assert.AreEqual("adobe.com-Tech@anonymised.email", record.TechnicalContact.Email);

            Assert.AreEqual(7, record.NameServers.Count);
            Assert.AreEqual("a1-217.akam.net", record.NameServers[0]);
            Assert.AreEqual("a10-64.akam.net", record.NameServers[1]);
            Assert.AreEqual("a13-65.akam.net", record.NameServers[2]);
            Assert.AreEqual("a26-66.akam.net", record.NameServers[3]);
            Assert.AreEqual("a28-67.akam.net", record.NameServers[4]);
            Assert.AreEqual("a7-64.akam.net", record.NameServers[5]);
            Assert.AreEqual("adobe-dns-01.adobe.com", record.NameServers[6]);

            Assert.AreEqual("Unsigned Delegation", record.DnsSecStatus);
            Assert.AreEqual("abuse@comlaude.com", record.Registrar.AbuseEmail);
            Assert.AreEqual("+44.2074218250", record.Registrar.AbuseTelephoneNumber);
        }
    }
}
