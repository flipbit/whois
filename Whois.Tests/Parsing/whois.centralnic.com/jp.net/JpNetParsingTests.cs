using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.JpNet
{
    [TestFixture]
    public class JpNetParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "jp.net", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "jp.net", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("ntt.jp.net", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO846061", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("GMO", response.Registrar.Name);
            Assert.AreEqual("http://www.onamae.com", response.Registrar.Url);
            Assert.AreEqual("+81 3 5456 1120", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 1, 24, 16, 57, 19, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2012, 3, 16, 11, 47, 23, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2018, 3, 16, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("136151BCEFE", response.Registrant.RegistryId);
            Assert.AreEqual("zhijian xia", response.Registrant.Name);
            Assert.AreEqual("zhijian xia", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(6, response.Registrant.Address.Count);
            Assert.AreEqual("Chuo", response.Registrant.Address[0]);
            Assert.AreEqual("3-23-20", response.Registrant.Address[1]);
            Assert.AreEqual("Warabi-shi", response.Registrant.Address[2]);
            Assert.AreEqual("Saitama", response.Registrant.Address[3]);
            Assert.AreEqual("335-0004", response.Registrant.Address[4]);
            Assert.AreEqual("JP", response.Registrant.Address[5]);

            Assert.AreEqual("+81.08037215656", response.Registrant.TelephoneNumber);
            Assert.AreEqual("xia@ingame.jp", response.Registrant.Email);


             // AdminContact Details
            Assert.AreEqual("136151BD1A1", response.AdminContact.RegistryId);
            Assert.AreEqual("zhijian xia", response.AdminContact.Name);
            Assert.AreEqual("zhijian xia", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(6, response.AdminContact.Address.Count);
            Assert.AreEqual("Chuo", response.AdminContact.Address[0]);
            Assert.AreEqual("3-23-20", response.AdminContact.Address[1]);
            Assert.AreEqual("Warabi-shi", response.AdminContact.Address[2]);
            Assert.AreEqual("Saitama", response.AdminContact.Address[3]);
            Assert.AreEqual("335-0004", response.AdminContact.Address[4]);
            Assert.AreEqual("JP", response.AdminContact.Address[5]);

            Assert.AreEqual("+81.08037215656", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("xia@ingame.jp", response.AdminContact.Email);


             // BillingContact Details
            Assert.AreEqual("136151BD74A", response.BillingContact.RegistryId);
            Assert.AreEqual("zhijian xia", response.BillingContact.Name);
            Assert.AreEqual("zhijian xia", response.BillingContact.Organization);

             // BillingContact Address
            Assert.AreEqual(5, response.BillingContact.Address.Count);
            Assert.AreEqual("Chuo", response.BillingContact.Address[0]);
            Assert.AreEqual("Warabi-shi", response.BillingContact.Address[1]);
            Assert.AreEqual("Saitama", response.BillingContact.Address[2]);
            Assert.AreEqual("335-0004", response.BillingContact.Address[3]);
            Assert.AreEqual("JP", response.BillingContact.Address[4]);

            Assert.AreEqual("+81.08037215656", response.BillingContact.TelephoneNumber);
            Assert.AreEqual("xia@ingame.jp", response.BillingContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("136151BD459", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Technical Contact", response.TechnicalContact.Name);
            Assert.AreEqual("GMO Internet Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(6, response.TechnicalContact.Address.Count);
            Assert.AreEqual("26-1 Sakuragaoka-cho", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Cerulean Tower 11F", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Shibuya-ku", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Tokyo", response.TechnicalContact.Address[3]);
            Assert.AreEqual("150-8512", response.TechnicalContact.Address[4]);
            Assert.AreEqual("JP", response.TechnicalContact.Address[5]);

            Assert.AreEqual("+81.0354562555", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("admin@onamae.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("dns1.onamae.com", response.NameServers[0]);
            Assert.AreEqual("dns2.onamae.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(57, response.FieldsParsed);
        }
    }
}
