using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Net.Sb.Sb
{
    [TestFixture]
    public class SbParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "not_found.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.sb", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "found.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("baidu.com.sb", response.DomainName.ToString());
            Assert.AreEqual("404765-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Key-Systems", response.Registrar.Name);
            Assert.AreEqual("http://www.key-systems.net", response.Registrar.Url);
            Assert.AreEqual("info@key-systems.net", response.Registrar.AbuseEmail);
            Assert.AreEqual("+49 (0)68949396850", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 02, 26, 05, 08, 41, 045, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 03, 27, 04, 29, 19, 249, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 03, 27, 04, 29, 19, 346, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("419751-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("long dian", response.Registrant.Name);
            Assert.AreEqual("999.cn.vc", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("shannxi", response.Registrant.Address[0]);
            Assert.AreEqual("xian", response.Registrant.Address[1]);
            Assert.AreEqual("710000", response.Registrant.Address[2]);
            Assert.AreEqual("CN", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("419751-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("long dian", response.AdminContact.Name);
            Assert.AreEqual("999.cn.vc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("shannxi", response.AdminContact.Address[0]);
            Assert.AreEqual("xian", response.AdminContact.Address[1]);
            Assert.AreEqual("710000", response.AdminContact.Address[2]);
            Assert.AreEqual("CN", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("419751-CoCCA", response.BillingContact.RegistryId);
            Assert.AreEqual("long dian", response.BillingContact.Name);
            Assert.AreEqual("999.cn.vc", response.BillingContact.Organization);
            Assert.AreEqual("+1.123456789", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.123456789", response.BillingContact.FaxNumber);
            Assert.AreEqual("hostcn@gmail.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("shannxi", response.BillingContact.Address[0]);
            Assert.AreEqual("xian", response.BillingContact.Address[1]);
            Assert.AreEqual("710000", response.BillingContact.Address[2]);
            Assert.AreEqual("CN", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("419751-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("long dian", response.TechnicalContact.Name);
            Assert.AreEqual("999.cn.vc", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.123456789", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.123456789", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostcn@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("shannxi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("xian", response.TechnicalContact.Address[1]);
            Assert.AreEqual("710000", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CN", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("f1g1ns1.dnspod.net", response.NameServers[0]);
            Assert.AreEqual("f1g1ns2.dnspod.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(48, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found_status_available()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "not_found_status_available.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound005", response.TemplateName);

            Assert.AreEqual("u34jedzcq.sb", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.net.sb", "sb", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.net.sb", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("baidu.com.sb", response.DomainName.ToString());
            Assert.AreEqual("404765-CoCCA", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Key-Systems", response.Registrar.Name);
            Assert.AreEqual("http://www.key-systems.net", response.Registrar.Url);
            Assert.AreEqual("info@key-systems.net", response.Registrar.AbuseEmail);
            Assert.AreEqual("+49 (0)68949396850", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2012, 02, 26, 05, 08, 41, 045, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2010, 03, 27, 04, 29, 19, 249, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 03, 27, 04, 29, 19, 346, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("419751-CoCCA", response.Registrant.RegistryId);
            Assert.AreEqual("long dian", response.Registrant.Name);
            Assert.AreEqual("999.cn.vc", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("shannxi", response.Registrant.Address[0]);
            Assert.AreEqual("xian", response.Registrant.Address[1]);
            Assert.AreEqual("710000", response.Registrant.Address[2]);
            Assert.AreEqual("CN", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("419751-CoCCA", response.AdminContact.RegistryId);
            Assert.AreEqual("long dian", response.AdminContact.Name);
            Assert.AreEqual("999.cn.vc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("shannxi", response.AdminContact.Address[0]);
            Assert.AreEqual("xian", response.AdminContact.Address[1]);
            Assert.AreEqual("710000", response.AdminContact.Address[2]);
            Assert.AreEqual("CN", response.AdminContact.Address[3]);


             // BillingContact Details
            Assert.AreEqual("419751-CoCCA", response.BillingContact.RegistryId);
            Assert.AreEqual("long dian", response.BillingContact.Name);
            Assert.AreEqual("999.cn.vc", response.BillingContact.Organization);
            Assert.AreEqual("+1.123456789", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("+1.123456789", response.BillingContact.FaxNumber);
            Assert.AreEqual("hostcn@gmail.com", response.BillingContact.Email);

             // BillingContact Address
            Assert.AreEqual(4, response.BillingContact.Address.Count);
            Assert.AreEqual("shannxi", response.BillingContact.Address[0]);
            Assert.AreEqual("xian", response.BillingContact.Address[1]);
            Assert.AreEqual("710000", response.BillingContact.Address[2]);
            Assert.AreEqual("CN", response.BillingContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("419751-CoCCA", response.TechnicalContact.RegistryId);
            Assert.AreEqual("long dian", response.TechnicalContact.Name);
            Assert.AreEqual("999.cn.vc", response.TechnicalContact.Organization);
            Assert.AreEqual("+1.123456789", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.123456789", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostcn@gmail.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("shannxi", response.TechnicalContact.Address[0]);
            Assert.AreEqual("xian", response.TechnicalContact.Address[1]);
            Assert.AreEqual("710000", response.TechnicalContact.Address[2]);
            Assert.AreEqual("CN", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("f1g1ns1.dnspod.net", response.NameServers[0]);
            Assert.AreEqual("f1g1ns2.dnspod.net", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(48, response.FieldsParsed);
        }
    }
}
