using NUnit.Framework;
using System;
using Whois.Models;

namespace Whois.Parsers
{
    [TestFixture]
    public class WhoisParserTests
    {
        private WhoisParser parser;
        private SampleReader sampleReader;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
            sampleReader = new SampleReader();
        }

        [Test]
        public void TestParseDomainNameWhois()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            var result = parser.Parse("capetown-whois.registry.net.za", "capetown", sample);

            Assert.IsNotNull(result);
            Assert.AreEqual("registry.capetown", result.DomainName);
            Assert.AreEqual(WhoisResponseStatus.Found, result.Status);
            Assert.AreEqual(5, parser.Templates.Count);
        }

        [Test]
        public void TestParseDomainNameWhoisDoesNotRegisterTemplateTwice()
        {
            var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found.txt");

            parser.Parse("capetown-whois.registry.net.za", "capetown", sample);
            parser.Parse("capetown-whois.registry.net.za", "capetown", sample);

            Assert.AreEqual(5, parser.Templates.Count);
        }

        [Test]
        public void TestParseRecord()
        {
            var sample = sampleReader.Read("whois.comlaude.com", "com", "adobe.com.txt");
            
            var record = parser.Parse("whoiscomlaude.com", "com", sample);

            Assert.AreEqual("adobe.com", record.DomainName);
            Assert.AreEqual("4364022_DOMAIN_COM-VRSN", record.RegistryDomainId);
            Assert.AreEqual("whois.comlaude.com", record.Registrar.WhoisServerUrl);
            Assert.AreEqual("http://www.comlaude.com", record.Registrar.Url);
            Assert.AreEqual(new DateTime(2018, 10, 18, 17, 9, 58), record.Updated.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(1986, 11, 17, 05, 0, 00), record.Registered.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2019, 05, 17, 00, 0, 00), record.Expiration.Value.ToUniversalTime());
            Assert.AreEqual("NOM-IQ Ltd dba Com Laude", record.Registrar.Name);
            Assert.AreEqual("470", record.Registrar.IanaId);
            Assert.AreEqual("clientUpdateProhibited", record.DomainStatus[0]);
            Assert.AreEqual("serverDeleteProhibited", record.DomainStatus[1]);
            Assert.AreEqual("serverTransferProhibited", record.DomainStatus[2]);
            Assert.AreEqual("serverUpdateProhibited", record.DomainStatus[3]);
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
        
        [Test]
        public void TestParseBrRecord()
        {
            var sample = sampleReader.Read("whois.registro.br", "br", "001hosting.com.br.txt");
            
            var record = parser.Parse("whois.registro.br", "br", sample);

            Assert.AreEqual("001hosting.com.br", record.DomainName);
            Assert.AreEqual("350.562.738-05", record.RegistryDomainId);
            Assert.AreEqual("Ultra Provedor", record.Registrar.Name);
            Assert.AreEqual(new DateTime(2019, 4, 6, 0, 0, 0), record.Updated.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2001, 9, 19, 0, 0, 0), record.Registered.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2020, 9, 19, 0, 0, 0), record.Expiration.Value.ToUniversalTime());
            Assert.AreEqual("ULPRO5", record.Registrant.Name);
            Assert.AreEqual("ULPRO5", record.AdminContact.Name);
            Assert.AreEqual("ULPRO5", record.TechnicalContact.Name);

            Assert.AreEqual(3, record.NameServers.Count);
            Assert.AreEqual("ns1.ultraprovedor.com.br", record.NameServers[0]);
            Assert.AreEqual("ns2.ultraprovedor.com.br", record.NameServers[1]);
            Assert.AreEqual("ns3.ultraprovedor.com.br", record.NameServers[2]);
        }

        [Test]
        public void TestParseHiChinaRecord()
        {
            var sample = sampleReader.Read("whois.cnnic.cn", "cn", "025bbs.cn.txt");

            var record = parser.Parse("whois.cnnic.cn", "cn", sample);

            Assert.AreEqual("20180313s10001s99456578-cn", record.RegistryDomainId);
            Assert.AreEqual("阿里云计算有限公司（万网）", record.Registrar.Name);
            Assert.AreEqual(new DateTime(2018, 3, 13, 21, 45, 16), record.Registered.Value.ToUniversalTime());
            Assert.AreEqual(new DateTime(2021, 3, 13, 21, 45, 16), record.Expiration.Value.ToUniversalTime());
            Assert.AreEqual("南京越之彬网络科技有限公司", record.Registrant.Name);
            Assert.AreEqual("hc1250473063700", record.Registrant.RegistryId);
            Assert.AreEqual("email@qq.com", record.Registrant.Email);

            Assert.AreEqual(2, record.NameServers.Count);
            Assert.AreEqual("dns27.hichina.com", record.NameServers[0]);
            Assert.AreEqual("dns28.hichina.com", record.NameServers[1]);
        }

        [Test]
        public void TestParsePlRecord()
        {
            var sample = sampleReader.Read("whois.dns.pl", "pl", "08.pl.txt");

            var record = parser.Parse("whois.dns.pl", "pl", sample);

            Assert.AreEqual("08.pl", record.DomainName);
        }

        [Test]
        public void TestParseJpRecord()
        {
            var sample = sampleReader.Read("whois.jprs.jp", "jp", "amazon.co.jp.txt");

            var record = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.AreEqual("amazon.co.jp", record.DomainName);
            Assert.AreEqual("Amazon, Inc.", record.Registrant.Name);
            Assert.AreEqual("JC076JP", record.AdminContact.Name);
            Assert.AreEqual("IK4644JP", record.TechnicalContact.Name);
            Assert.AreEqual(4, record.NameServers.Count);
            Assert.AreEqual("ns1.p31.dynect.net", record.NameServers[0]);
            Assert.AreEqual("ns2.p31.dynect.net", record.NameServers[1]);
            Assert.AreEqual("pdns1.ultradns.net", record.NameServers[2]);
            Assert.AreEqual("pdns6.ultradns.co.uk", record.NameServers[3]);
            Assert.AreEqual(new DateTime(2002, 11, 21), record.Registered);
            Assert.AreEqual(new DateTime(2018, 12, 01), record.Updated);
        }
        
        [Test]
        public void TestParseDeRecord()
        {
            var sample = sampleReader.Read("whois.denic.de", "de", "amazon.de.txt");
            
            var record = parser.Parse("whois.denic.de", "de", sample);

            Assert.AreEqual("amazon.de", record.DomainName);
        }

        [Test]
        public void TestParseJpAltRecord()
        {
            var sample = sampleReader.Read("whois.jprs.jp", "jp", "ameblo.jp.txt");
            
            var record = parser.Parse("whois.jprs.jp", "jp", sample);

            Assert.AreEqual("ameblo.jp", record.DomainName);
            Assert.AreEqual("CyberAgent, Inc.", record.Registrant.Name);
            Assert.AreEqual(6, record.NameServers.Count);
            Assert.AreEqual("a1-5.akam.net", record.NameServers[0]);
            Assert.AreEqual("a11-66.akam.net", record.NameServers[1]);
            Assert.AreEqual("a20-67.akam.net", record.NameServers[2]);
            Assert.AreEqual("a4-64.akam.net", record.NameServers[3]);
            Assert.AreEqual("a6-65.akam.net", record.NameServers[4]);
            Assert.AreEqual("a7-66.akam.net", record.NameServers[5]);
            Assert.AreEqual(new DateTime(2004, 7, 30), record.Registered);
            Assert.AreEqual(new DateTime(2019, 7, 31), record.Expiration);
            Assert.AreEqual(new DateTime(2018, 8, 1), record.Updated);
            Assert.AreEqual("CyberAgent, Inc.", record.AdminContact.Name);
            Assert.AreEqual("dns-ssl-info@cyberagent.co.jp", record.AdminContact.Email);
            Assert.AreEqual(3, record.AdminContact.Address.Count);
            Assert.AreEqual("Shibuya-ku", record.AdminContact.Address[0]);
            Assert.AreEqual("19-1 Maruyamacho", record.AdminContact.Address[1]);
            Assert.AreEqual("Shibuya Prime Plaza 2F", record.AdminContact.Address[2]);
            Assert.AreEqual("03-5459-6150", record.AdminContact.TelephoneNumber);
            Assert.AreEqual("03-5784-7070", record.AdminContact.FaxNumber);
        }   

        [Test]
        public void TestParseCzRecord()
        {
            var sample = sampleReader.Read("whois.nic.cz", "cz", "phoca.cz.txt");
            
            var record = parser.Parse("whois.nic.cz", "cz", sample);

            Assert.AreEqual("CZ.NIC", record.TemplateName);

            Assert.AreEqual("phoca.cz", record.DomainName);

            Assert.AreEqual("REG-ZONER", record.Registrar.Name);

            Assert.AreEqual(new DateTime(2007, 8, 8, 7, 15, 0), record.Registered);
            Assert.AreEqual(new DateTime(2012, 4, 4, 4, 37, 56), record.Updated);
            Assert.AreEqual(new DateTime(2019, 8, 8), record.Expiration);
        }
    }
}
