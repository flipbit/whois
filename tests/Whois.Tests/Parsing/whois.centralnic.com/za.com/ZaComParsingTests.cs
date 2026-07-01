using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.ZaCom
{
    [TestFixture]
    public class ZaComParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.centralnic.com", "za.com", "not_found.txt");
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
            var sample = SampleReader.Read("whois.centralnic.com", "za.com", "found.txt");
            var response = parser.Parse("whois.centralnic.com", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.centralnic.com/Found", response.TemplateName);

            Assert.AreEqual("siyenza.za.com", response.DomainName.ToString());
            Assert.AreEqual("CNIC-DO333077", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("Megaweb Internet Services", response.Registrar.Name);
            Assert.AreEqual("http://www.megaweb.co.za/", response.Registrar.Url);
            Assert.AreEqual("02711 485 1984", response.Registrar.AbuseTelephoneNumber);

            Assert.AreEqual(new DateTime(2013, 12, 3, 12, 33, 13, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 11, 17, 11, 47, 29, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 11, 17, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("H1063006", response.Registrant.RegistryId);
            Assert.AreEqual("MegaWeb Internet Services cc", response.Registrant.Name);
            Assert.AreEqual("+27.0114851984", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@megaweb.co.za", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("PO Box 3738", response.Registrant.Address[0]);
            Assert.AreEqual("Cramerview", response.Registrant.Address[1]);
            Assert.AreEqual("2060", response.Registrant.Address[2]);
            Assert.AreEqual("ZA", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("H119106", response.AdminContact.RegistryId);
            Assert.AreEqual("Liz Hart", response.AdminContact.Name);
            Assert.AreEqual("Siyenza Management", response.AdminContact.Organization);
            Assert.AreEqual("+27.0114851984", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@megaweb.co.za", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("PO Box 3738", response.AdminContact.Address[0]);
            Assert.AreEqual("Cramerview", response.AdminContact.Address[1]);
            Assert.AreEqual("2060", response.AdminContact.Address[2]);
            Assert.AreEqual("ZA", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("C12112", response.TechnicalContact.RegistryId);
            Assert.AreEqual("Laida Peters", response.TechnicalContact.Name);
            Assert.AreEqual("Megaweb Internet Services", response.TechnicalContact.Organization);
            Assert.AreEqual("+27.027114851984", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("dns-admin@megaweb.co.za", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Gauteng", response.TechnicalContact.Address[0]);
            Assert.AreEqual("2192", response.TechnicalContact.Address[1]);
            Assert.AreEqual("ZA", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1a.your-server.co.za", response.NameServers[0]);
            Assert.AreEqual("nsa.second-ns.co.za", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);

            Assert.AreEqual("Unsigned", response.DnsSecStatus);
            Assert.AreEqual(38, response.FieldsParsed);
        }
    }
}
